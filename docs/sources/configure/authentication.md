---
title: Authentication
menuTitle: Authentication
description: Authenticate the Grafana MCP server with a service account or delegate each user's Cloudflare Access identity to Grafana.
keywords:
  - authentication
  - service account
  - token
  - MCP
weight: 1
aliases:
  - /docs/grafana-cloud/machine-learning/mcp/configure/authentication/
---

# Authentication

The Grafana MCP server needs an identity to call the Grafana API. For automation, use a service account token. For a remote employee-facing server, Cloudflare Access can delegate each authenticated user's identity so Grafana applies that user's own RBAC permissions.

## What you'll achieve

You configure either a machine identity or per-user Cloudflare Access delegation. Machine credentials work with every transport; Cloudflare Access delegation requires SSE or streamable HTTP.

## Before you begin

- A Grafana instance (Grafana 9.0 or later).
- For token auth: a [service account](https://grafana.com/docs/grafana/latest/administration/service-accounts/#add-a-token-to-a-service-account-in-grafana) with a token and the RBAC permissions needed for the tools you use.
- For Cloudflare Access: separate self-hosted Access applications for the MCP server and Grafana, with Grafana already configured to authenticate users from the Access identity.

## Use a service account token

Set `GRAFANA_URL` and `GRAFANA_SERVICE_ACCOUNT_TOKEN` in the environment passed to the server.

- **GRAFANA_URL:** Your Grafana base URL (for example, `http://localhost:3000` or `https://myinstance.grafana.net`).
- **GRAFANA_SERVICE_ACCOUNT_TOKEN:** The token you created for the service account.

The deprecated `GRAFANA_API_KEY` is still supported but will be removed in a future version; use `GRAFANA_SERVICE_ACCOUNT_TOKEN` instead.

### Read the token from a file

Set `GRAFANA_SERVICE_ACCOUNT_TOKEN_FILE` to a file path that contains the token instead of passing the value inline. The file is read fresh on every request, so a rotated token is picked up automatically without restarting the server.

This is useful in Kubernetes, where a Secret mounted as a volume is updated in place when the underlying Secret changes. Because the server's client cache is keyed on the token value, a rotated token transparently produces a new client with no pod restart:

```yaml
env:
  - name: GRAFANA_SERVICE_ACCOUNT_TOKEN_FILE
    value: /var/run/secrets/grafana/token
volumeMounts:
  - name: grafana-token
    mountPath: /var/run/secrets/grafana
    readOnly: true
volumes:
  - name: grafana-token
    secret:
      secretName: grafana-mcp-token
```

Surrounding whitespace (including a trailing newline) is trimmed from the file contents. If both `GRAFANA_SERVICE_ACCOUNT_TOKEN` and `GRAFANA_SERVICE_ACCOUNT_TOKEN_FILE` are set, the inline token takes precedence.

## Use username and password

You can use basic auth by setting `GRAFANA_USERNAME` and `GRAFANA_PASSWORD` instead of a token. This is less suitable for automation; prefer a service account token when possible.

## Delegate Cloudflare Access user identity

Use this mode for a remote MCP endpoint when both the MCP server and Grafana are protected by Cloudflare Access. It gives users a normal browser sign-in through your configured identity provider; the MCP client stores only Cloudflare's short-lived OAuth grant, and Grafana authorizes every tool call as the signed-in user.

### Configure Cloudflare Access

1. Create a self-hosted Access application for the MCP endpoint and enable [Managed OAuth](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/). Configure the identity providers and Access policies employees must pass.
2. Copy the MCP application's **Application Audience (AUD) Tag** and your Access team domain.
3. On the Access application protecting Grafana, add a **Service Auth** policy with the **Linked App Token** selector and select the MCP application. Refer to [Allow MCP servers to access self-hosted applications](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/linked-apps/).
4. Keep both origins unreachable except through Cloudflare Access. The MCP origin independently validates the assertion, but an exposed Grafana or authentication-proxy origin could bypass Access entirely.

The browser-facing OAuth token terminates at Cloudflare. Access sends the MCP origin a signed, MCP-audience JWT; after validating it, `mcp-grafana` forwards that assertion to the Grafana Access application as `Cf-Access-Token`. The linked-app policy is the explicit delegation boundary. The user's OAuth bearer is never forwarded to Grafana.

### Configure mcp-grafana

Set the Grafana URL and three Cloudflare variables:

```bash
GRAFANA_URL=https://grafana.example.com
MCP_GRAFANA_CLOUDFLARE_ACCESS_ENABLED=true
MCP_GRAFANA_CLOUDFLARE_ACCESS_TEAM_DOMAIN=https://example.cloudflareaccess.com
MCP_GRAFANA_CLOUDFLARE_ACCESS_AUDIENCE=<MCP_APPLICATION_AUD_TAG>
```

Use streamable HTTP for new deployments. Configure `--allowed-hosts` with the public MCP hostname, for example:

```bash
mcp-grafana --transport streamable-http --address 0.0.0.0:8000 --allowed-hosts mcp.example.com
```

Do not configure `MCP_GRAFANA_SERVER_TOKEN`, a Grafana service account/API token, basic authentication, or credential-bearing `GRAFANA_EXTRA_HEADERS` / `GRAFANA_FORWARD_HEADERS` in this mode. The server refuses to start if these authentication methods are combined, preventing a failed user assertion from falling back to a privileged static credential.

After an MCP client is given `https://mcp.example.com/mcp`, Cloudflare's discovery metadata makes the client open a browser. The user completes the existing SSO flow and returns to the client automatically. Cloudflare can use short-lived access tokens with longer-lived refresh grants so routine reconnects do not repeatedly prompt the user.

The server verifies the Access signature using Cloudflare's rotating keys and requires the configured issuer, MCP application audience, expiration, application-token type, non-empty subject, and verified email. Machine service-token assertions are rejected because they do not represent a Grafana user. Grafana remains the authorization authority: its existing auth proxy must map the propagated signed identity to the correct Grafana account, organization, teams, and role.

When `MCP_GRAFANA_CLOUDFLARE_ACCESS_ENABLED` is unset or `false`, existing service account and basic-auth behavior is unchanged. Prefer separate deployments or hostnames for employee delegation and machine automation so each endpoint has one unambiguous authentication policy.

## Next steps

- [Enable and disable tools](../enable-and-disable-tools/) to control which MCP tools are available.
- [Transports and addresses](../transports-and-addresses/) for stdio, SSE, and streamable-http.
