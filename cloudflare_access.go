package mcpgrafana

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

const (
	cloudflareAccessAssertionHeader = "Cf-Access-Jwt-Assertion"
	cloudflareAccessTokenHeader     = "Cf-Access-Token"
	defaultCloudflareVerifyTimeout  = 10 * time.Second
)

// CloudflareAccessConfig configures validation of the identity assertion that
// Cloudflare Access adds after completing Managed OAuth at the edge.
type CloudflareAccessConfig struct {
	// TeamDomain is the exact Cloudflare Access issuer, for example
	// https://example.cloudflareaccess.com.
	TeamDomain string
	// Audience is the AUD tag of the Access application protecting this MCP server.
	Audience string

	// HTTPClient is used to retrieve Cloudflare's rotating signing keys. It is
	// optional and primarily useful to embedders and tests.
	HTTPClient *http.Client
	// VerificationTimeout bounds signing-key retrieval. Zero uses 10 seconds.
	VerificationTimeout time.Duration
}

type cloudflareAccessIdentity struct {
	assertion string
	subject   string
}

type cloudflareAccessIdentityContextKey struct{}

// NewCloudflareAccessMiddleware constructs middleware which validates the
// Cloudflare Access application JWT before an MCP request reaches any tool.
// The client-facing OAuth bearer is stripped and is never made available to
// Grafana transports. Only identity-based Access JWTs are accepted: service
// token assertions have an empty subject and are deliberately rejected.
func NewCloudflareAccessMiddleware(cfg CloudflareAccessConfig, logger *slog.Logger) (func(http.Handler) http.Handler, error) {
	teamDomain, err := normalizeCloudflareTeamDomain(cfg.TeamDomain)
	if err != nil {
		return nil, err
	}
	audience := strings.TrimSpace(cfg.Audience)
	if audience == "" {
		return nil, fmt.Errorf("Cloudflare Access audience must not be empty")
	}
	if logger == nil {
		logger = slog.Default()
	}
	timeout := cfg.VerificationTimeout
	if timeout <= 0 {
		timeout = defaultCloudflareVerifyTimeout
	}
	client := &http.Client{Timeout: timeout}
	if cfg.HTTPClient != nil {
		clientCopy := *cfg.HTTPClient
		if clientCopy.Timeout <= 0 || clientCopy.Timeout > timeout {
			clientCopy.Timeout = timeout
		}
		client = &clientCopy
	}

	keySetContext := oidc.ClientContext(context.Background(), client)
	keySet := oidc.NewRemoteKeySet(keySetContext, teamDomain+"/cdn-cgi/access/certs")
	verifier := oidc.NewVerifier(teamDomain, keySet, &oidc.Config{
		ClientID:             audience,
		SupportedSigningAlgs: []string{oidc.RS256},
	})

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// A preflight has no credentials and cannot invoke an MCP operation.
			if r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}

			assertion := strings.TrimSpace(r.Header.Get(cloudflareAccessAssertionHeader))
			if assertion == "" {
				rejectCloudflareAccessRequest(w, r, logger, "missing Cloudflare Access assertion")
				return
			}

			verifyCtx, cancel := context.WithTimeout(r.Context(), timeout)
			verifyCtx = oidc.ClientContext(verifyCtx, client)
			token, err := verifier.Verify(verifyCtx, assertion)
			cancel()
			if err != nil {
				rejectCloudflareAccessRequest(w, r, logger, "invalid Cloudflare Access assertion")
				return
			}

			var claims struct {
				Email              string `json:"email"`
				Type               string `json:"type"`
				ServiceTokenStatus bool   `json:"service_token_status"`
			}
			if err := token.Claims(&claims); err != nil {
				rejectCloudflareAccessRequest(w, r, logger, "invalid Cloudflare Access claims")
				return
			}
			issuedAtInvalid := token.IssuedAt.IsZero() || token.IssuedAt.After(time.Now().Add(5*time.Minute))
			if strings.TrimSpace(token.Subject) == "" || strings.TrimSpace(claims.Email) == "" || claims.Type != "app" || claims.ServiceTokenStatus || issuedAtInvalid {
				rejectCloudflareAccessRequest(w, r, logger, "Cloudflare Access assertion does not represent an interactive user")
				return
			}

			// Carry the verified assertion in a private context value, then remove
			// every inbound authentication credential. This prevents either the
			// OAuth bearer or caller-supplied Grafana credentials from reaching the
			// Grafana client, its cache keys, or logs.
			requestContext := context.WithValue(r.Context(), cloudflareAccessIdentityContextKey{}, cloudflareAccessIdentity{
				assertion: assertion,
				subject:   token.Subject,
			})
			clean := r.Clone(requestContext)
			clean.Header = r.Header.Clone()
			for _, name := range []string{
				"Authorization",
				cloudflareAccessAssertionHeader,
				cloudflareAccessTokenHeader,
				grafanaServiceAccountTokenHeader,
				grafanaAPIKeyHeader,
			} {
				clean.Header.Del(name)
			}
			next.ServeHTTP(w, clean)
		})
	}, nil
}

func normalizeCloudflareTeamDomain(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("Cloudflare Access team domain must be an HTTPS origin such as https://example.cloudflareaccess.com")
	}
	return "https://" + u.Host, nil
}

func rejectCloudflareAccessRequest(w http.ResponseWriter, r *http.Request, logger *slog.Logger, reason string) {
	logger.Warn("Rejected request without a valid Cloudflare Access user identity",
		"remote_addr", r.RemoteAddr,
		"method", r.Method,
		"path", r.URL.Path,
		"reason", reason,
	)
	w.Header().Set("WWW-Authenticate", "Bearer")
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func cloudflareAccessAssertionFromContext(ctx context.Context) (string, bool) {
	identity, ok := ctx.Value(cloudflareAccessIdentityContextKey{}).(cloudflareAccessIdentity)
	return identity.assertion, ok && identity.assertion != ""
}

func cloudflareAccessSubjectFromContext(ctx context.Context) (string, bool) {
	identity, ok := ctx.Value(cloudflareAccessIdentityContextKey{}).(cloudflareAccessIdentity)
	return identity.subject, ok && identity.subject != ""
}

// applyCloudflareAccessIdentity selects user-delegated Grafana authentication
// for the current request. It deliberately clears every other authentication
// method so a missing or malformed identity can never fall back to a more
// privileged static credential.
func applyCloudflareAccessIdentity(ctx context.Context, cfg *GrafanaConfig) {
	assertion, ok := cloudflareAccessAssertionFromContext(ctx)
	if !ok {
		return
	}
	cfg.APIKey = ""
	cfg.BasicAuth = nil
	cfg.AccessToken = ""
	cfg.IDToken = ""
	if cfg.ExtraHeaders == nil {
		cfg.ExtraHeaders = make(map[string]string, 1)
	}
	for name := range cfg.ExtraHeaders {
		if isAuthenticationHeader(name) {
			delete(cfg.ExtraHeaders, name)
		}
	}
	cfg.ExtraHeaders[cloudflareAccessTokenHeader] = assertion
}

func isAuthenticationHeader(name string) bool {
	for _, sensitive := range []string{
		"Authorization",
		"Cookie",
		cloudflareAccessAssertionHeader,
		cloudflareAccessTokenHeader,
		"Cf-Access-Client-Id",
		"Cf-Access-Client-Secret",
		grafanaServiceAccountTokenHeader,
		grafanaAPIKeyHeader,
		"X-Access-Token",
		"X-Grafana-Id",
	} {
		if strings.EqualFold(name, sensitive) {
			return true
		}
	}
	return false
}
