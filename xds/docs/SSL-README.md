# SSL Certificate Management for XDS Service

This feature adds automatic SSL certificate management using Let's Encrypt via CertMagic.

## Features

- Automatic certificate acquisition from Let's Encrypt
- HTTP-01 ACME challenge support
- Certificate renewal automation
- Support for staging and production Let's Encrypt environments
- Domain-based certificate management

## Configuration

### Environment Variables

- `SSL_ENABLE`: Enable/disable SSL certificate management (true/false, default: false)
- `SSL_STAGING`: Use Let's Encrypt staging environment (true/false, default: false)
- `SSL_ACME_EMAIL`: Email address for ACME account (required)
- `CERT_HTTP_PORT`: Port for HTTP-01 challenge server (default: 8080)
- `XDG_DATA_HOME`: Base directory for certificate storage (default: ~/.local/share)

### YAML Configuration

Add the following to your `gateway-auth.yaml`:

```yaml
# SSL Certificate Management
ssl:
  enabled: true                    # Enable certificate management
  staging: false                   # Use Let's Encrypt production
  acme_email: your-email@example.com
  http_port: 8080                 # Port for HTTP-01 challenges
  storage_path: /srv/var/ssl      # Certificate storage path

# Per-client TLS configuration
clients:
  - id: my_service
    domain: example.com           # Domain name
    tls: true                     # Request certificate for this domain
    # ... other config
```

## How It Works

1. **Certificate Request**: When a client has `tls: true` and a valid `domain`, the XDS server will request a certificate for that domain.

2. **HTTP-01 Challenge**: The server starts an HTTP server on the configured port (default 8080) to handle ACME HTTP-01 challenges from Let's Encrypt.

3. **Certificate Storage**: Certificates are stored in the configured storage path:
   - Production: `{storage_path}/certificates/acme-v02.api.letsencrypt.org-directory/{domain}/`
   - Staging: `{storage_path}/certificates/acme-staging-v02.api.letsencrypt.org-directory/{domain}/`

4. **Automatic Renewal**: CertMagic automatically manages certificate renewal before expiration.

## Prerequisites

1. **Domain Control**: You must control the domain(s) for which you're requesting certificates.

2. **Network Access**:
   - The HTTP-01 challenge port (default 8080) must be accessible from the internet
   - Your domain must point to the server running the XDS service

3. **Firewall Rules**: Ensure the challenge port is open for incoming connections from Let's Encrypt servers.

## Testing

### Local Testing (with staging)

```bash
# Set environment variables
export SSL_ENABLE=true
export SSL_STAGING=true
export SSL_ACME_EMAIL=your-email@example.com
export CERT_HTTP_PORT=8080

# Run the server
./xds-server -config gateway-auth-ssl.yaml
```

### Production Deployment

1. Ensure your domain points to your server
2. Open port 80 or your configured `CERT_HTTP_PORT`
3. Set `staging: false` in configuration
4. Run the service

## Certificate Files

Once obtained, certificates are stored as:
- Certificate: `{domain}.crt`
- Private Key: `{domain}.key`
- Metadata: `{domain}.json`

## Troubleshooting

1. **Challenge Failures**:
   - Verify the domain points to your server
   - Check firewall rules for the HTTP port
   - Review logs for specific error messages

2. **Rate Limits**:
   - Let's Encrypt has rate limits
   - Use staging environment for testing
   - Production: 50 certificates per domain per week

3. **Storage Issues**:
   - Ensure write permissions for storage path
   - Check disk space availability

## Security Considerations

- Private keys are stored on disk with restrictive permissions (0600)
- Use appropriate file system permissions for the storage directory
- Consider using a dedicated service account for the XDS server
- Regularly backup your certificates and keys

## Integration with Envoy

The certificates obtained can be used to configure TLS termination in Envoy. The listener configuration will be updated in a future release to automatically use the obtained certificates.