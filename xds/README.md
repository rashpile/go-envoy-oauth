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

Edit `gateway-auth.yaml` to configure:
- OAuth settings (issuer, client ID/secret)
- Backend clusters (address, port, SSL)
- Routing rules and path exclusions

Example:
```yaml
plugin:
  library_path: /app/go-envoy-oauth.so
oauth:
  issuer_url: "https://your-idp.example.com"
  client_id: "your-client-id"
  client_secret: "your-secret"
clients:
  - id: backend_service
    address: api.example.com
    port: 443
    ssl: true
    prefix: /api
    exclude_paths: ["/health", "/metrics"]
```

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