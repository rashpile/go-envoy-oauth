# XDS Server for go-envoy-oauth

This is an xDS control plane server that dynamically configures Envoy with OAuth authentication using the go-envoy-oauth plugin.

## Features

- Dynamic configuration via xDS v3 protocol
- Serves CDS, EDS, LDS, and RDS resources
- File-based configuration with hot reload
- Integrates with existing go-envoy-oauth plugin

## Directory Structure

```
xds/
├── app/
│   ├── main.go           # Entry point
│   ├── server.go         # XDS server implementation
│   ├── config.go         # Config parser for gateway-auth.yaml
│   └── resources.go      # XDS resource builders
├── envoy-xds.yaml        # Envoy bootstrap config
├── gateway-auth.yaml     # OAuth & routing configuration
├── run.sh                # Build and run script
└── README.md             # This file
```

## Configuration

Edit `gateway-auth.yaml` to configure OAuth settings, listener, and backend clients.

### Complete Configuration Example

```yaml
plugin:
  library_path: /app/go-envoy-oauth.so

listener:
  address: 0.0.0.0
  port: 8080
  tls_port: 8443  # Optional, for HTTPS

default_provider: keycloak
providers:
  keycloak:
    issuer_url: "${OIDC_ISSUER_URL}"
    client_id: "${OIDC_CLIENT_ID}"
    client_secret: "${OIDC_CLIENT_SECRET}"
    redirect_url: "/oauth/callback"
    scopes: ["openid", "profile", "email"]

# Legacy single-provider format (still supported):
# oauth:
#   issuer_url: "https://your-idp.example.com"
#   client_id: "your-client-id"
#   client_secret: "your-client-secret"

  # Session configuration
  session_cookie_name: "session"
  session_max_age: 86400  # 24 hours in seconds
  session_path: "/"
  session_secure: true
  session_http_only: true
  session_same_site: "Lax"

  # Optional features
  enable_api_key: false       # Enable API key generation
  enable_bearer_token: true   # Enable bearer token authentication

clients:
  - id: backend_service       # Required: Unique cluster identifier
    address: api.example.com  # Required: Backend hostname/IP
    port: 443                 # Default: 8080
    ssl: true                 # Default: false - Use SSL for upstream
    domain: "app.example.com" # Optional: Route specific domain to this client
    prefix: /api              # Default: "/" - Path prefix for routing
    exclude: false            # Default: false - Bypass authentication
    exclude_paths:            # Optional: Specific paths to exclude
      - /health
      - /metrics
    host_rewrite: "api.example.com"  # Optional: Rewrite Host header
    prefix_rewrite: "/v2"     # Optional: Rewrite path prefix for upstream
    add_token: true           # Default: false - Add Authorization header
    cluster_idle_timeout: "300s"     # Optional: Connection idle timeout
    route_timeout: "15s"      # Optional: Per-route timeout

    # SSO injection (optional)
    sso_injection: true
    sso_appurl: "https://app.example.com"
    sso_appname: "My Application"
```

### Configuration Sections

#### Plugin Configuration

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `library_path` | No | `/app/go-envoy-oauth.so` | Path to the filter shared object file |

#### Listener Configuration

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `address` | No | `0.0.0.0` | Listener address |
| `port` | No | `8080` | HTTP listener port |
| `tls_port` | No | - | HTTPS listener port (enables TLS when set) |

#### Provider Configuration (Multi-Provider)

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `default_provider` | No | - | Fallback provider name for clients without an explicit `provider` field |
| `providers` | No | - | Map of named provider configs. Each entry: `issuer_url`, `client_id`, `client_secret`, `redirect_url`, `scopes`, `allowed_users` |

The legacy `oauth:` block (single flat config) is still supported and treated as a provider named `default`.

#### Environment Variable Substitution

`gateway-auth.yaml` supports `${VAR}` substitution from the process environment. Variables are expanded before YAML parsing, making it safe to inject secrets at runtime:

```yaml
providers:
  keycloak:
    client_secret: "${OIDC_CLIENT_SECRET}"
```

Unset variables expand to an empty string.

#### OAuth Session Configuration

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `session_cookie_name` | No | `session` | Session cookie name |
| `session_max_age` | No | `86400` | Session expiration in seconds |
| `session_path` | No | `/` | Cookie path |
| `session_secure` | No | `true` | Secure cookie flag |
| `session_http_only` | No | `true` | HttpOnly cookie flag |
| `session_same_site` | No | `Lax` | SameSite cookie attribute |
| `enable_api_key` | No | `false` | Enable API key generation feature |
| `enable_bearer_token` | No | `true` | Enable bearer token authentication |

#### Client Configuration

Each client in the `clients` array represents a backend service cluster.

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `id` | Yes | - | Unique identifier for the Envoy cluster |
| `description` | No | - | Free-form text describing this client. Operator-facing only — not sent to Envoy or the filter |
| `enabled` | No | `true` | Set to `false` to keep the client entry in YAML history but skip it during xDS generation (no cluster, no route, no filter config) |
| `address` | Yes | - | Backend service hostname or IP |
| `port` | No | `8080` | Backend service port |
| `ssl` | No | `false` | Use SSL/TLS for upstream connections |
| `tls` | No | `false` | Request Let's Encrypt certificate for this domain |
| `domain` | No | - | Route requests for specific domain(s). Supports comma-separated multiple domains |
| `prefix` | No | `/` | URL path prefix for routing |
| `exclude` | No | `false` | Bypass authentication for all requests to this service |
| `exclude_paths` | No | `[]` | List of specific paths to exclude from authentication |
| `host_rewrite` | No | - | Rewrite the Host header for upstream requests |
| `prefix_rewrite` | No | - | Rewrite path prefix for upstream requests (see [Path Rewriting](#path-rewriting)) |
| `provider` | No | `default_provider` | Named provider to use for this client |
| `allowed_users` | No | `[]` | Usernames permitted to access this client (matched against `preferred_username` claim, case-insensitive). Use `["*"]` to allow any authenticated user. If empty, the user must match the resolved provider's `allowed_users` to be permitted, otherwise access is denied. |
| `add_token` | No | `false` | Add `Authorization: Bearer <token>` header to upstream |
| `cluster_idle_timeout` | No | - | Connection idle timeout (e.g., `300s`) |
| `route_timeout` | No | - | Request timeout for this route (e.g., `15s`) |
| `sso_injection` | No | `false` | Inject this app into SSO portal |
| `sso_appurl` | No | - | Application URL for SSO portal |
| `sso_appname` | No | - | Display name in SSO portal |

### Multi-Domain Routing Example

```yaml
clients:
  # Route multiple domains to the same backend
  - id: web_app
    address: web-backend
    port: 8080
    domain: "app.example.com,www.example.com"
    prefix: /
    sso_injection: true
    sso_appurl: "https://app.example.com"
    sso_appname: "Web App"

  # Domain-specific API routing
  - id: api_service
    address: api-backend
    port: 9000
    domain: "api.example.com"
    prefix: /v1
    add_token: true
    route_timeout: "30s"

  # Public service without authentication
  - id: public_site
    address: public-backend
    port: 8080
    domain: "public.example.com"
    exclude: true
```

### Disabling Clients

Set `enabled: false` on a client to keep its YAML block in the file (preserving
configuration history) while having the xDS server skip it entirely. A disabled
client produces no cluster, no route, no per-cluster filter config, and no TLS
certificate request — Envoy never sees it. Flip the flag back to `true` (or
remove it) to re-enable the client; the xDS server applies the change on the
next config reload, with no restart required.

The `description` field is free-form operator-facing metadata. It is read by
the YAML parser but never propagated to Envoy or the filter, so it is safe to
use for context such as ownership, migration status, or rollback notes.

```yaml
clients:
  - id: legacy_api
    description: "v1 of the auth API; kept for rollback during the v2 migration"
    address: legacy-backend
    port: 8080
    domain: "legacy.example.com"
    enabled: false   # kept for history; Envoy ignores this client
```

`enabled` and `exclude` are independent: `exclude: true` bypasses
authentication while still routing the client; `enabled: false` removes the
client from the gateway entirely.

### Path Rewriting

The `prefix_rewrite` option allows you to rewrite the request path before forwarding to the upstream service. This is useful when the external path structure differs from the internal service paths.

#### How It Works

Path rewriting uses regex substitution to transform incoming request paths:
- The `prefix` defines what paths to match
- The `prefix_rewrite` defines the new prefix for upstream requests

#### Examples

**Example 1: Rewrite to different path**
```yaml
clients:
  - id: api_v1
    address: backend
    port: 8080
    prefix: /api
    prefix_rewrite: /v1
```
- Request: `/api/users` → Upstream: `/v1/users`
- Request: `/api/posts/123` → Upstream: `/v1/posts/123`

**Example 2: Strip prefix completely**
```yaml
clients:
  - id: echo_service
    address: http-echo
    port: 8080
    prefix: /echo
    prefix_rewrite: /
```
- Request: `/echo/test` → Upstream: `/test`
- Request: `/echo/foo/bar` → Upstream: `/foo/bar`

**Example 3: Rewrite for legacy API paths**
```yaml
clients:
  - id: legacy_api
    address: old-service
    port: 9000
    prefix: /new-api
    prefix_rewrite: /api/v2
```
- Request: `/new-api/resource` → Upstream: `/api/v2/resource`

**Example 4: Combine with host rewrite**
```yaml
clients:
  - id: external_service
    address: internal-backend
    port: 8080
    domain: "api.example.com"
    prefix: /external
    prefix_rewrite: /internal
    host_rewrite: "internal.service.local"
```
- Request to `api.example.com/external/data`
- Upstream receives: Host: `internal.service.local`, Path: `/internal/data`

## Building and Running

### Build XDS Server
```bash
go build -o xds-server ./app
```

### Run XDS Server
```bash
./xds-server --config=gateway-auth.yaml --port=18000
```

Or use the provided script:
```bash
./run.sh
```

### Run Envoy with XDS
```bash
envoy -c envoy-xds.yaml
```

Or with Docker:
```bash
docker run -v $(pwd):/app -v $(pwd)/../:/plugin \
  envoyproxy/envoy:v1.33-latest \
  -c /app/envoy-xds.yaml
```

## Testing

1. Start the XDS server:
   ```bash
   ./run.sh
   ```

2. In another terminal, start Envoy:
   ```bash
   envoy -c envoy-xds.yaml
   ```

3. Verify resources are loaded:
   ```bash
   curl localhost:9901/clusters
   curl localhost:9901/config_dump
   ```

4. Test OAuth flow:
   ```bash
   curl localhost:8080
   # Should redirect to OAuth provider
   ```

## Hot Reload

The XDS server watches `gateway-auth.yaml` for changes. When you modify the file, it automatically:
1. Reloads the configuration
2. Generates new xDS resources
3. Updates Envoy without restart

## Troubleshooting

- Check XDS server logs for configuration errors
- Use Envoy admin interface (port 9901) to inspect loaded configuration
- Verify the OAuth plugin (.so file) path is correct
- Ensure all required OAuth fields are configured

## Dependencies

- Go 1.23+
- Envoy v1.33+
- go-envoy-oauth plugin (built from parent project)