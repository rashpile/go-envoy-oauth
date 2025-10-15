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

oauth:
  issuer_url: "https://your-idp.example.com"
  client_id: "your-client-id"
  client_secret: "your-client-secret"
  redirect_url: "/oauth/callback"
  scopes: ["openid", "profile", "email"]

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

#### OAuth Configuration

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `issuer_url` | Yes | - | OAuth/OIDC provider issuer URL |
| `client_id` | Yes | - | OAuth client ID |
| `client_secret` | No | - | OAuth client secret |
| `redirect_url` | No | `/oauth/callback` | OAuth callback path |
| `scopes` | No | `["openid", "profile", "email"]` | OAuth scopes |
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