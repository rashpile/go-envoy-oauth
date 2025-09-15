# Template Configuration Support

The XDS server now supports using Envoy configuration templates to extend the base OAuth configuration with additional resources like clusters, listeners, routes, and endpoints.

## Usage

### 1. Via CLI Flag
```bash
./xds-server --config gateway-auth.yaml --template my-template.yaml
```

### 2. Via Configuration File
Add the `template` field to your `gateway-auth.yaml`:
```yaml
template: path/to/template.yaml

plugin:
  library_path: /app/go-envoy-oauth.so
oauth:
  issuer_url: https://auth.example.com
  # ... rest of config
```

## Template Structure

The template file should contain Envoy resources in YAML format. The XDS server supports all common Envoy filter types including:
- HTTP filters (cors, header_to_metadata, rate_limit, jwt_authn, etc.)
- Network filters (tcp_proxy, redis_proxy, etc.)
- Access loggers (file, stdout, grpc)
- Transport sockets (TLS configurations)

Template format:

```yaml
# Additional listeners
listeners:
  - name: admin_listener
    address:
      socket_address:
        address: 0.0.0.0
        port_value: 9901
    # ... listener config

# Additional clusters
clusters:
  - name: logging_service
    type: STRICT_DNS
    lb_policy: ROUND_ROBIN
    # ... cluster config

# Additional routes
routes:
  - name: custom_routes
    virtual_hosts:
      - name: health_checks
        # ... route config

# Additional endpoints
endpoints:
  - cluster_name: my_cluster
    endpoints:
      # ... endpoint config
```

## Merging Behavior

### Listeners
- **Different names**: Template listeners are added alongside the OAuth listener
- **Same name (listener_0)**: Template listener is merged with OAuth listener:
  - Template listener settings (address, timeouts, etc.) are preserved
  - OAuth filter is intelligently inserted into the HTTP filter chain
  - OAuth filter is placed before the router filter for proper request interception
  - Additional filter chains from template are preserved

### HTTP Filter Merging (for listener_0)
When the template defines `listener_0` with HTTP filters:
1. All non-router filters from the template are preserved in their original order
2. The OAuth filter (`envoy.filters.http.golang`) is automatically injected after template filters
3. The router filter is always placed last (terminal position) to ensure proper request handling
4. If template doesn't include a router filter, one is automatically added from the OAuth configuration

**Filter Order Examples:**
- Template has `[header_to_metadata, router]` → Result: `[header_to_metadata, oauth_filter, router]`
- Template has `[cors, header_to_metadata]` (no router) → Result: `[cors, header_to_metadata, oauth_filter, router]`
- Template has `[custom_filter]` → Result: `[custom_filter, oauth_filter, router]`

**Important:** The router filter must always be the last filter in the chain as it's a terminal filter

### Clusters
- Template clusters are added alongside gateway-configured clusters
- Gateway clusters take precedence if names conflict

### Routes
- Template routes are merged into the main route configuration
- Additional virtual hosts can be added
- Separate route configurations are preserved

### Endpoints
- Template endpoints are added alongside any gateway endpoints

## Live Reload

Both the main configuration and template files are watched for changes. When either file is modified, the XDS snapshot is automatically updated.

## Example

See `example-template.yaml` for a complete example that adds:
- Admin listener for stats and health checks
- Additional upstream clusters
- Custom routing rules

## Environment Variables

Template path can also be overridden using environment variables (following the same pattern as OAuth config):
- CLI flag takes highest precedence
- Config file `template` field is next
- Environment variables can override OAuth settings

## Troubleshooting

### Common Issues

1. **"non-terminal filter ... is the last filter in a http filter chain"**
   - Ensure your template includes a router filter at the end, or let the XDS server add it automatically
   - The router filter is automatically placed last during merging

2. **"unable to resolve type.googleapis.com/..."**
   - The XDS server includes most common Envoy types
   - If you encounter this error, the filter type may not be available in the current version

3. **Template not being applied**
   - Check XDS server logs: `docker exec envoy-gateway tail -f /tmp/xds-server.log`
   - Verify template path is correct in gateway-auth.yaml
   - Ensure template YAML syntax is valid