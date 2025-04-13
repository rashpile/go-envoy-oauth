# go-envoy-oauth

A Go-based HTTP filter for Envoy Proxy that provides API key authentication. This filter allows you to secure your APIs by validating requests against a configured set of API keys before they reach your backend services. The filter validates API keys and maps them to usernames, simplifying the authentication process for clients.

## Features

- Simple API key authentication via HTTP headers or query parameters
- Flexible precedence rules when both header and query parameter contain keys
- API key to username mapping
- Flexible key source interface for different storage backends
- Easy integration with Envoy Proxy's filter chain
- Configurable paths for authentication bypass
- Customizable header names and authentication schemes

## How It Works

The filter intercepts incoming HTTP requests at the Envoy gateway and:

1. Extracts the API key from either request headers or query parameters (based on configuration)
2. Validates the key against a configured key source
3. Maps the API key to a username
4. Adds the username to request headers for downstream services
5. Allows valid requests to proceed to backend services
6. Rejects invalid requests with appropriate HTTP status codes

## Quick Start

### Prerequisites

- Docker
- Go 1.22+
- Envoy Proxy (v1.33+)

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

# Test an authenticated request with header
curl -H "X-API-Key: 12345" http://localhost:10000/get

# Test an authenticated request with query parameter
curl "http://localhost:10000/get?x-api-key=12345"

# Test an unauthenticated request (should be rejected)
curl http://localhost:10000/get
```

## Configuration

### Envoy Configuration

Add the filter to your Envoy configuration:

```yaml
http_filters:
- name: envoy.filters.http.golang
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.golang.v3alpha.Config
    library_id: go-envoy-keyauth
    library_path: "/app/go-envoy-keyauth.so"
    plugin_name: go-envoy-keyauth
    plugin_config:
      "@type": type.googleapis.com/xds.type.v3.TypedStruct
      value:
        # API key header configuration
        api_key_header: "X-API-Key"    # Header to extract API key from

        # API key query parameter configuration
        api_key_query_param: "x-api-key"  # Query parameter to extract API key from (set to empty string to disable)
        header_precedence: true  # If true, header takes precedence when both are present

        # Username configuration
        username_header: "X-User-ID"  # Header to set with username for backend services

        # Key source configuration
        keys_file: "/etc/envoy/api-keys.txt"  # Path to API keys file
        check_interval: 60  # How often to check for file changes (in seconds)

        # Authentication bypass configuration
        exclude_paths: ["/health", "/metrics"]  # Paths to exclude from auth
```

### API Key Configuration

Create a file with key:username pairs, one per line:

```
12345:admin
abc123456key:username1
xyz789012key:username2
```

The filter will:
1. Extract the API key from the request (header or query parameter)
2. Look up the corresponding username
3. Add the username to the request headers for backend services

## Authentication Options

### Header-based Authentication

The filter will look for the API key in the configured HTTP header (default: `X-API-Key`).

Example:
```bash
curl -H "X-API-Key: 12345" http://localhost:10000/get
```

### Query Parameter Authentication

The filter will look for the API key in the configured query parameter (default: `x-api-key`).

Example:
```bash
curl "http://localhost:10000/get?x-api-key=12345"
```

### Authentication Precedence

When both header and query parameter contain API keys, the `header_precedence` configuration determines which one is used:

- `header_precedence: true` (default): Header takes precedence over query parameter
- `header_precedence: false`: Query parameter takes precedence over header

### Disabling Query Parameter Authentication

To disable query parameter authentication completely, set `api_key_query_param` to an empty string:

```yaml
api_key_query_param: ""  # Disables query parameter authentication
```

## Extending

### Implementing a Custom Key Source

You can implement the `KeySource` interface to support different key storage backends:

```go
type CustomKeySource struct {
    // Your fields here
}

func (s *CustomKeySource) GetUsername(apiKey string) (string, error) {
    // Your implementation here that returns username for the given API key
    // Return empty string and error if key is invalid
}
```

## Development

### Project Structure

- `auth/` - Authentication interfaces and implementations
- `filter/` - Envoy filter implementation
- `example/` - Example configuration for testing

### Testing

```bash
# Run tests
go test ./...
```

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
