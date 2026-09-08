package mcpgrafana

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type cloudflareAccessTestIssuer struct {
	server *httptest.Server
	signer jose.Signer
}

func newCloudflareAccessTestIssuer(t *testing.T) *cloudflareAccessTestIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "test-key", Algorithm: string(jose.RS256), Use: "sig"}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/cdn-cgi/access/certs", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}))
	}))
	t.Cleanup(server.Close)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key"),
	)
	require.NoError(t, err)
	return &cloudflareAccessTestIssuer{server: server, signer: signer}
}

func (i *cloudflareAccessTestIssuer) token(t *testing.T, overrides map[string]any) string {
	t.Helper()
	claims := map[string]any{
		"iss":   i.server.URL,
		"aud":   []string{"mcp-audience"},
		"sub":   "user-id-123",
		"email": "user@example.com",
		"type":  "app",
		"iat":   time.Now().Add(-time.Minute).Unix(),
		"nbf":   time.Now().Add(-time.Minute).Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	}
	for key, value := range overrides {
		claims[key] = value
	}
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	signed, err := i.signer.Sign(payload)
	require.NoError(t, err)
	compact, err := signed.CompactSerialize()
	require.NoError(t, err)
	return compact
}

func newCloudflareAccessTestMiddleware(t *testing.T, issuer *cloudflareAccessTestIssuer, logger *slog.Logger) func(http.Handler) http.Handler {
	t.Helper()
	middleware, err := NewCloudflareAccessMiddleware(CloudflareAccessConfig{
		TeamDomain: issuer.server.URL,
		Audience:   "mcp-audience",
		HTTPClient: issuer.server.Client(),
	}, logger)
	require.NoError(t, err)
	return middleware
}

func TestCloudflareAccessMiddlewareAcceptsInteractiveUserAndStripsCredentials(t *testing.T) {
	issuer := newCloudflareAccessTestIssuer(t)
	assertion := issuer.token(t, nil)
	middleware := newCloudflareAccessTestMiddleware(t, issuer, nil)
	t.Setenv("GRAFANA_URL", "https://grafana.example.com")
	t.Setenv("GRAFANA_SERVICE_ACCOUNT_TOKEN", "server-side-static-token")
	t.Setenv("GRAFANA_USERNAME", "static-admin")
	t.Setenv("GRAFANA_PASSWORD", "static-password")
	t.Setenv("GRAFANA_EXTRA_HEADERS", `{"Authorization":"Bearer configured-secret","X-Custom":"preserved"}`)

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		got, ok := cloudflareAccessAssertionFromContext(r.Context())
		assert.True(t, ok)
		assert.Equal(t, assertion, got)
		subject, ok := cloudflareAccessSubjectFromContext(r.Context())
		assert.True(t, ok)
		assert.Equal(t, "user-id-123", subject)
		for _, name := range []string{
			"Authorization",
			cloudflareAccessAssertionHeader,
			cloudflareAccessTokenHeader,
			grafanaServiceAccountTokenHeader,
			grafanaAPIKeyHeader,
		} {
			assert.Empty(t, r.Header.Get(name), name)
		}
		ctx := ExtractGrafanaInfoFromHeaders(r.Context(), r)
		cfg := GrafanaConfigFromContext(ctx)
		assert.Empty(t, cfg.APIKey)
		assert.Nil(t, cfg.BasicAuth)
		assert.Equal(t, assertion, cfg.ExtraHeaders[cloudflareAccessTokenHeader])
		assert.Equal(t, "preserved", cfg.ExtraHeaders["X-Custom"])
		assert.NotContains(t, cfg.ExtraHeaders, "Authorization")
		_, apiKey, basicAuth, _ := extractKeyGrafanaInfoFromReq(r, slog.Default())
		assert.Empty(t, apiKey)
		assert.Nil(t, basicAuth)
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set(cloudflareAccessAssertionHeader, assertion)
	req.Header.Set("Authorization", "Bearer oauth:client-facing-secret")
	req.Header.Set(cloudflareAccessTokenHeader, "caller-supplied-token")
	req.Header.Set(grafanaServiceAccountTokenHeader, "caller-supplied-grafana-token")
	req.Header.Set(grafanaAPIKeyHeader, "caller-supplied-api-key")
	rec := httptest.NewRecorder()
	middleware(inner).ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

func TestCloudflareAccessMiddlewareRejectsInvalidOrNonUserAssertions(t *testing.T) {
	issuer := newCloudflareAccessTestIssuer(t)
	var logBuffer bytes.Buffer
	middleware := newCloudflareAccessTestMiddleware(t, issuer, slog.New(slog.NewTextHandler(&logBuffer, nil)))

	tests := []struct {
		name      string
		assertion string
	}{
		{name: "missing"},
		{name: "wrong audience", assertion: issuer.token(t, map[string]any{"aud": []string{"grafana-audience"}})},
		{name: "wrong issuer", assertion: issuer.token(t, map[string]any{"iss": "https://attacker.example"})},
		{name: "expired", assertion: issuer.token(t, map[string]any{"exp": time.Now().Add(-time.Hour).Unix()})},
		{name: "future not-before", assertion: issuer.token(t, map[string]any{"nbf": time.Now().Add(time.Hour).Unix()})},
		{name: "missing issued-at", assertion: issuer.token(t, map[string]any{"iat": nil})},
		{name: "future issued-at", assertion: issuer.token(t, map[string]any{"iat": time.Now().Add(time.Hour).Unix()})},
		{name: "service token", assertion: issuer.token(t, map[string]any{"sub": "", "email": "", "common_name": "machine.access"})},
		{name: "service token status", assertion: issuer.token(t, map[string]any{"service_token_status": true})},
		{name: "missing email", assertion: issuer.token(t, map[string]any{"email": ""})},
		{name: "global token", assertion: issuer.token(t, map[string]any{"type": "org"})},
		{name: "tampered", assertion: issuer.token(t, nil) + "tampered"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			inner := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
			req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			if tt.assertion != "" {
				req.Header.Set(cloudflareAccessAssertionHeader, tt.assertion)
			}
			rec := httptest.NewRecorder()
			middleware(inner).ServeHTTP(rec, req)

			assert.False(t, called)
			assert.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.Equal(t, "Bearer", rec.Header().Get("WWW-Authenticate"))
			assert.Equal(t, "unauthorized\n", rec.Body.String())
		})
	}

	logs := logBuffer.String()
	assert.NotContains(t, logs, "user@example.com")
	assert.NotContains(t, logs, "oauth:")
	for _, tt := range tests {
		if tt.assertion != "" {
			assert.NotContains(t, logs, tt.assertion)
		}
	}
}

func TestCloudflareAccessMiddlewareAllowsPreflightWithoutCredentials(t *testing.T) {
	issuer := newCloudflareAccessTestIssuer(t)
	middleware := newCloudflareAccessTestMiddleware(t, issuer, nil)
	called := false
	rec := httptest.NewRecorder()
	middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(
		rec,
		httptest.NewRequest(http.MethodOptions, "/mcp", nil),
	)
	assert.True(t, called)
}

func TestNewCloudflareAccessMiddlewareValidatesConfiguration(t *testing.T) {
	tests := []struct {
		name       string
		teamDomain string
		audience   string
	}{
		{name: "empty domain", audience: "aud"},
		{name: "http domain", teamDomain: "http://team.cloudflareaccess.com", audience: "aud"},
		{name: "domain with path", teamDomain: "https://team.cloudflareaccess.com/path", audience: "aud"},
		{name: "domain with credentials", teamDomain: "https://user@team.cloudflareaccess.com", audience: "aud"},
		{name: "empty audience", teamDomain: "https://team.cloudflareaccess.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewCloudflareAccessMiddleware(CloudflareAccessConfig{TeamDomain: tt.teamDomain, Audience: tt.audience}, nil)
			assert.Error(t, err)
		})
	}
}

func TestApplyCloudflareAccessIdentityUsesOnlyLinkedAppToken(t *testing.T) {
	ctx := contextWithCloudflareAssertion("verified-user-assertion")
	cfg := GrafanaConfig{
		APIKey:      "static-service-token",
		BasicAuth:   url.UserPassword("admin", "password"),
		AccessToken: "cloud-access-token",
		IDToken:     "cloud-id-token",
		ExtraHeaders: map[string]string{
			"Authorization":  "Bearer configured-secret",
			"Cookie":         "session=secret",
			"X-Access-Token": "configured-access-secret",
			"X-Custom":       "preserved",
		},
	}

	applyCloudflareAccessIdentity(ctx, &cfg)

	assert.Empty(t, cfg.APIKey)
	assert.Nil(t, cfg.BasicAuth)
	assert.Empty(t, cfg.AccessToken)
	assert.Empty(t, cfg.IDToken)
	assert.Equal(t, "verified-user-assertion", cfg.ExtraHeaders[cloudflareAccessTokenHeader])
	assert.Equal(t, "preserved", cfg.ExtraHeaders["X-Custom"])
	for name := range cfg.ExtraHeaders {
		if name != cloudflareAccessTokenHeader {
			assert.False(t, isAuthenticationHeader(name), name)
		}
	}
}

func TestApplyCloudflareAccessIdentityLeavesExistingAuthUntouchedWithoutIdentity(t *testing.T) {
	cfg := GrafanaConfig{APIKey: "existing-service-token"}
	applyCloudflareAccessIdentity(t.Context(), &cfg)
	assert.Equal(t, "existing-service-token", cfg.APIKey)
}

func contextWithCloudflareAssertion(assertion string) context.Context {
	return contextWithCloudflareIdentity(assertion, "user-id-123")
}

func contextWithCloudflareIdentity(assertion, subject string) context.Context {
	return context.WithValue(context.Background(), cloudflareAccessIdentityContextKey{}, cloudflareAccessIdentity{assertion: assertion, subject: subject})
}

func TestCloudflareAccessCacheKeyIsolatesUsersWithoutRetainingIdentity(t *testing.T) {
	requestFor := func(assertion, subject string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		return req.WithContext(contextWithCloudflareIdentity(assertion, subject))
	}

	first := cacheKeyFromRequest("https://grafana.example.com", "", nil, 1, requestFor("assertion-one", "user-one"))
	refreshed := cacheKeyFromRequest("https://grafana.example.com", "", nil, 1, requestFor("assertion-two", "user-one"))
	secondUser := cacheKeyFromRequest("https://grafana.example.com", "", nil, 1, requestFor("assertion-three", "user-two"))

	assert.Equal(t, first, refreshed, "a token refresh for the same user must reuse the client")
	assert.NotEqual(t, first, secondUser, "different users must never share a cached client")
	assert.Equal(t, first.singleflightKey(), refreshed.singleflightKey())
	assert.NotEqual(t, first.singleflightKey(), secondUser.singleflightKey())
	for _, secretOrIdentity := range []string{"assertion-one", "assertion-two", "user-one", "user-two"} {
		assert.NotContains(t, first.String(), secretOrIdentity)
		assert.NotContains(t, secondUser.String(), secretOrIdentity)
	}
}

func TestNormalizeCloudflareTeamDomain(t *testing.T) {
	got, err := normalizeCloudflareTeamDomain("  https://team.cloudflareaccess.com/  ")
	require.NoError(t, err)
	assert.Equal(t, "https://team.cloudflareaccess.com", got)
	assert.False(t, strings.HasSuffix(got, "/"))
}
