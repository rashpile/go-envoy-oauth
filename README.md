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
- Go 1.23+
- Envoy Proxy (v1.33+)
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

### Envoy Configuration

Add the filter to your Envoy configuration:

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
        # OpenID Connect configuration
        issuer_url: "https://your-oauth-provider.com"
        client_id: "your-client-id"
        client_secret: "your-client-secret"
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
        skip_auth_header_name: "X-Skip-Auth"

        # Optional features
        enable_api_key: false       # Enable API key generation
        enable_bearer_token: true   # Enable bearer token authentication

        # Global paths excluded from authentication
        exclude_paths: ["/health"]

        # Cluster-specific configurations
        clusters:
          backend_service_cluster:
            exclude_paths: ["/status", "/metrics"]
          public_api_cluster:
            exclude: true  # Bypass auth for entire cluster
          protected_api_cluster:
            add_token: true  # Add Authorization header with token
```

#### Cluster Configuration Options

The `clusters` section allows per-cluster authentication settings. Each cluster name must match the cluster name defined in your Envoy route configuration.

**Available cluster options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `exclude` | boolean | false | Bypass authentication for all requests to this cluster |
| `exclude_paths` | string[] | [] | Specific paths to exclude from authentication |
| `add_token` | boolean | false | Add `Authorization: Bearer <token>` header to upstream requests |

**Example with multiple clusters:**

```yaml
clusters:
  # Public endpoints - no authentication required
  health_cluster:
    exclude: true

  # API with selective path exclusion
  api_cluster:
    exclude_paths:
      - /health
      - /metrics
      - /version

  # Protected service that needs the token
  backend_cluster:
    add_token: true
```

### OAuth Provider Configuration

You'll need to configure your OAuth provider with:
- Client ID and Secret
- Redirect URL (matching the `redirect_url` in the Envoy config)
- Required scopes (typically "openid", "profile", "email")

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
