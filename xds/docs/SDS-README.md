# SDS (Secret Discovery Service) for Dynamic TLS Certificates

## Overview

The XDS server now includes an integrated SDS server that dynamically serves TLS certificates to Envoy. When TLS is enabled, certificates are automatically exposed to Envoy via the SDS protocol, allowing for seamless certificate rotation without proxy restarts.

## How It Works

1. **Automatic SDS Server**: When `ssl.enabled: true` is configured, the XDS server automatically starts an SDS service
2. **Certificate Discovery**: SDS monitors the certificate storage directory and automatically detects new/updated certificates
3. **Dynamic Updates**: When certificates are renewed or added, SDS pushes updates to Envoy without requiring restarts
4. **File Watching**: The SDS server uses `fsnotify` to watch for certificate file changes in real-time

## Configuration

### Enable SDS in your gateway configuration:

```yaml
# Enable TLS on the listener
listener:
  address: 0.0.0.0
  port: 8443
  tls: true          # This triggers SDS configuration

# Enable SSL certificate management
ssl:
  enabled: true      # This starts the SDS server
  storage_path: /srv/var/ssl
  # ... other SSL config

# Configure domains for TLS
clients:
  - id: my_service
    domain: example.com
    tls: true        # Request certificate for this domain
```

## Certificate Storage Structure

SDS expects certificates in the CertMagic storage format:
```
{storage_path}/
└── certificates/
    └── acme-v02.api.letsencrypt.org-directory/
        └── example.com/
            ├── example.com.crt
            └── example.com.key
```

For staging environment:
```
{storage_path}/
└── certificates/
    └── acme-staging-v02.api.letsencrypt.org-directory/
        └── example.com/
            ├── example.com.crt
            └── example.com.key
```

## SDS Secret Naming

Certificates are exposed as SDS secrets with predictable names:
- `server_cert_example_com` - Domain-specific certificate
- `default_server_cert` - Default certificate (first available)

## Envoy Configuration

When TLS is enabled, the XDS server automatically configures Envoy listeners with SDS:

```yaml
filter_chains:
- transport_socket:
    name: envoy.transport_sockets.tls
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
      common_tls_context:
        tls_certificate_sds_secret_configs:
        - name: server_cert_example_com
          sds_config:
            resource_api_version: V3
            ads: {}  # Uses Aggregated Discovery Service
```

## Features

### Automatic Certificate Reloading
- File system watching detects certificate changes
- Updates are pushed to Envoy within 500ms (debounced)
- No manual intervention required

### Multi-Domain Support
- Each domain gets its own SDS secret
- SNI-based routing supported
- Automatic fallback to default certificate

### Zero-Downtime Updates
- Certificate rotation happens without dropping connections
- New connections use updated certificates immediately
- Existing connections continue with old certificates until closed

## Monitoring

Watch the logs for SDS activity:
```
SDS: Loaded certificate for domain example.com as secret server_cert_example_com
SDS: Updated secret snapshot to version v2 with 2 secrets
SDS: Certificate file changed: .../example.com.crt
SDS: Certificate change detected, reloading...
```

## Troubleshooting

### Certificates Not Appearing in Envoy

1. Check that certificates exist in the expected directory structure
2. Verify SDS server started: look for "SDS service registered" in logs
3. Ensure `listener.tls: true` and `ssl.enabled: true` are both set
4. Check file permissions on certificate files

### Certificate Updates Not Detected

1. Verify fsnotify is watching the correct directories (check logs)
2. Ensure certificate files are being written atomically
3. Check for "Certificate change detected" messages in logs

### SDS Connection Issues

1. Ensure Envoy is configured to use ADS (Aggregated Discovery Service)
2. Verify gRPC connection between Envoy and XDS server
3. Check that SDS service is registered on the same gRPC server

## Testing

### Manual Certificate Testing

1. Start XDS server with SDS enabled:
```bash
./xds-server -config gateway-auth-ssl.yaml
```

2. Place test certificates in the storage directory:
```bash
mkdir -p /srv/var/ssl/certificates/acme-staging-v02.api.letsencrypt.org-directory/example.com/
cp test.crt /srv/var/ssl/certificates/.../example.com/example.com.crt
cp test.key /srv/var/ssl/certificates/.../example.com/example.com.key
```

3. Watch logs for SDS loading the certificates

4. Verify Envoy receives certificates:
```bash
# Check Envoy admin interface
curl http://localhost:9901/config_dump | grep -A 10 "secret"
```

## Benefits of SDS

- **Dynamic Updates**: No Envoy restarts required for certificate changes
- **Automatic Discovery**: New certificates are detected and served automatically
- **Centralized Management**: All certificates managed through single SDS endpoint
- **Security**: Secrets are not stored in Envoy config dumps
- **Production Ready**: Standard Envoy pattern for enterprise deployments