# go-envoy-oauth

A Go-based HTTP filter for Envoy Proxy that provides OAuth 2.0 and OpenID Connect authentication. This filter allows you to secure your APIs by authenticating requests against an OAuth provider before they reach your backend services.

## Features

- OAuth 2.0 and OpenID Connect authentication
- Session management with configurable cookie settings
- Support for multiple OAuth providers
- Flexible path-based authentication rules
- Cluster-specific authentication configurations
- User information propagation via headers
- Secure cookie handling with configurable attributes
- Support for token refresh
- Configurable authentication bypass options

## How It Works

The filter intercepts incoming HTTP requests at the Envoy gateway and:

1. Checks if the request path is excluded from authentication
2. Validates the session cookie if present
3. For unauthenticated requests, redirects to the OAuth provider's login page
4. Handles OAuth callbacks and creates sessions
5. Adds user information to request headers for downstream services
6. Allows valid requests to proceed to backend services
7. Rejects invalid requests with appropriate HTTP status codes

## Quick Start

### Prerequisites

- Docker
- Go 1.25+
- Envoy Proxy v1.39.x (the Envoy release must match the `github.com/envoyproxy/envoy` Go SDK version in `go.mod`; the standalone image is built on `envoyproxy/envoy:contrib-v1.39.2`)
- OAuth provider (e.g., Keycloak, Auth0, etc.)

### Building the Filter

```bash
# Build the shared object file
make build
```

This will create the filter shared object file in the `dist` directory.

### Running the Example

```bash
# Start the example Envoy configuration
make start

# Access your application through the Envoy proxy
curl http://localhost:8080/your-endpoint
```

## Configuration

### Provider Configuration

Providers are declared in a top-level `providers` map and referenced by name in each cluster. A `default_provider` is used for any cluster without an explicit `provider` field, and for legacy single-provider configs that omit the `providers` map entirely.

```yaml
plugin_config:
  "@type": type.googleapis.com/xds.type.v3.TypedStruct
  value:
    # --- Multi-provider setup ---
    default_provider: keycloak   # fallback when cluster has no 'provider' field

    providers:
      keycloak:
        issuer_url: "https://keycloak.example.com/realms/myrealm"
        client_id: "my-client"
        client_secret: "my-secret"
        redirect_url: "/oauth/callback"
        scopes: ["openid", "profile", "email"]

      google:
        issuer_url: "https://accounts.google.com"
        client_id: "google-client-id"
        client_secret: "google-client-secret"
        redirect_url: "/oauth/callback"
        scopes: ["openid", "profile", "email"]
```

Each provider value supports these fields:

| Field | Required | Description |
|-------|----------|-------------|
| `issuer_url` | yes | OIDC issuer URL; discovery doc fetched from `<issuer_url>/.well-known/openid-configuration` |
| `client_id` | yes | OAuth client ID |
| `client_secret` | yes | OAuth client secret |
| `redirect_url` | yes | Callback path registered with the provider (e.g. `/oauth/callback`) |
| `scopes` | no | Additional scopes (default `openid profile email`) |
| `allowed_users` | no | Lowercased usernames or emails granted access to all clusters served by this provider (OR-grant). Use `["*"]` to permit any authenticated user from this provider. |

#### Legacy single-provider format (backward compatible)

Configs without a `providers` map continue to work. The top-level `issuer_url`, `client_id`, `client_secret`, `redirect_url`, and `scopes` fields are automatically treated as a provider named `default`:

```yaml
value:
  issuer_url: "https://your-provider.com"
  client_id: "your-client-id"
  client_secret: "your-client-secret"
  redirect_url: "/oauth/callback"
  scopes: ["openid", "profile", "email"]
```

### Envoy Filter Configuration

Full plugin config with all options:

```yaml
http_filters:
- name: envoy.filters.http.golang
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.golang.v3alpha.Config
    library_id: gateway-auth
    library_path: "/app/go-envoy-oauth.so"
    plugin_name: gateway-auth
    plugin_config:
      "@type": type.googleapis.com/xds.type.v3.TypedStruct
      value:
        # Provider registry
        default_provider: keycloak
        providers:
          keycloak:
            issuer_url: "https://keycloak.example.com/realms/myrealm"
            client_id: "my-client"
            client_secret: "my-secret"
            redirect_url: "/oauth/callback"
            scopes: ["openid", "profile", "email"]

        # Session configuration
        session_cookie_name: "session"
        session_max_age: 86400  # 24 hours in seconds
        session_path: "/"
        session_domain: "localhost"
        session_secure: true
        session_http_only: true
        session_same_site: "Lax"

        # Header configuration
        user_id_header_name: "X-User-ID"
        user_email_header_name: "X-User-Email"
        user_username_header_name: "X-User-Username"
        auth_provider_header_name: "X-Auth-Provider"  # verified provider key on downstream requests
        skip_auth_header_name: "X-Skip-Auth"

        # Identity headers stripped from inbound requests to prevent spoofing.
        # auth_provider_header_name is always enforced here regardless of this list.
        remove_headers:
          - "X-User-ID"
          - "X-User-Email"
          - "X-User-Username"
          - "X-Auth-Provider"

        # Optional features
        enable_api_key: false       # Enable API key generation
        enable_bearer_token: true   # Enable bearer token authentication

        # Global paths excluded from authentication
        exclude_paths: ["/health"]

        # Cluster-specific configurations
        clusters:
          keycloak_service_cluster:
            provider: keycloak       # routes this cluster through the keycloak provider
          google_service_cluster:
            provider: google
            add_token: true
          public_api_cluster:
            exclude: true
```

#### Cluster Configuration Options

The `clusters` section maps Envoy cluster names to per-cluster auth settings.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `provider` | string | `default_provider` | Named provider to use for this cluster |
| `exclude` | boolean | false | Bypass authentication for all requests to this cluster |
| `exclude_paths` | string[] | [] | Paths to exclude from authentication within this cluster |
| `add_token` | boolean | false | Add `Authorization: Bearer <token>` header to upstream requests |
| `allowed_users` | string[] | [] | Usernames permitted to access this cluster (matched against `preferred_username` claim, case-insensitive). Use `["*"]` to allow any authenticated user. If empty, the user must match the resolved provider's `allowed_users` to be permitted, otherwise access is denied. |

### Provider Health

Each provider tracks independent health state. A provider whose OIDC discovery fails at startup is registered as `down` and immediately returns 503 for all requests — other providers continue serving normally.

Down providers **self-heal without a config reload**. A background goroutine retries OIDC discovery with exponential backoff (5 s → 5 min, ±20% jitter). On success the provider is atomically promoted to `ready` and the JWKS refresh loop starts. This resolves the common startup race where the IdP itself sits behind Envoy and is not yet reachable when the filter initializes.

After startup, a background goroutine per provider refreshes JWKS with exponential backoff:

| State | Meaning | Requests |
|-------|---------|---------|
| `ready` | Last JWKS refresh succeeded | Served normally |
| `degraded` | One or more consecutive failures, last-known-good JWKS still valid | Served normally |
| `down` | Startup discovery failed, OR stale threshold exceeded; recovery retried in background | 503 returned |

**Prometheus metrics:**

```
envoy_oauth_idp_state{idp="keycloak", state="ready"}    1
envoy_oauth_idp_state{idp="keycloak", state="degraded"} 0
envoy_oauth_idp_state{idp="keycloak", state="down"}     0
envoy_oauth_idp_up{idp="keycloak"}                      1
```

The `idp` label matches the provider name from the `providers` map.

### OIDC Provider Setup

You'll need to register the callback URL with your OIDC provider:
- **Redirect URI**: `https://your-domain.com/oauth/callback`
- **Scopes**: `openid profile email` (plus any custom scopes)
- **Grant type**: Authorization Code (PKCE is always enabled)

## Environment Variables

The filter supports the following environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | INFO | Logging level (DEBUG, INFO, WARN, ERROR) |
| `ACCESS_LOG` | - | Access log format (plain, json) |
| `METRICS_PORT` | (disabled) | Port for Prometheus metrics endpoint. If unset, metrics server is disabled. |

**Metrics Endpoint:**

When `METRICS_PORT` is set (e.g., `9102`), the filter exposes a `/metrics` endpoint with:
- Go runtime metrics (`go_goroutines`, `go_memstats_*`)
- Process metrics (`process_cpu_seconds_total`, `process_resident_memory_bytes`)

Example:
```bash
curl http://localhost:9102/metrics
```

**Breaking change:** The top-level `super_users` config field has been removed. Configs that still include `super_users:` will have those entries silently ignored — affected users will be denied access. Migrate by moving usernames into the `allowed_users` field of the relevant provider entry (for OR-grant access across all clusters) or the cluster's `allowed_users` field.

**Breaking change (Phase 04):** The `idp` Prometheus label on OAuth metrics
(`envoy_oauth_login_total`, `envoy_oauth_logout_total`, `envoy_oauth_session_*`,
`envoy_oauth_token_validation_*`, `envoy_oauth_callback_duration_seconds_*`)
now carries the provider registry key from the `providers` config map
(e.g., `keycloak`, `google`) instead of the issuer hostname (e.g.,
`keycloak.example.com`). Update any Grafana dashboards or Prometheus alert
rules that filter on the old hostname values.

## Authentication Flow

1. **Initial Request**: User accesses a protected resource
2. **Session Check**: Filter checks for valid session cookie
3. **Authentication**:
   - If no valid session, redirects to OAuth provider
   - User authenticates with provider
   - Provider redirects back to callback URL
4. **Session Creation**: Filter creates session and sets cookie
5. **Request Processing**: Filter adds user info to headers and forwards request

## Session Management

The filter provides configurable session management with:
- Secure cookie settings
- Session expiration
- Token refresh support
- Configurable cookie attributes (domain, path, secure, etc.)

## Development

### Project Structure

- `filter/` - Envoy filter implementation
- `oauth/` - OAuth handler implementation
- `session/` - Session management
- `config/` - Configuration types and parsing
- `example/` - Example configurations

### Testing

```bash
# Run tests
make test

# Run tests with coverage
make test-coverage
```

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
