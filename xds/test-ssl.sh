#!/bin/bash

# Test script for SSL certificate management
# This script tests the certificate HTTP challenge server

echo "Testing SSL Certificate Management"
echo "=================================="
echo ""

# Set environment variables for testing
export SSL_ENABLE=true
export SSL_STAGING=true
export SSL_ACME_EMAIL=koptilin@gmail.com
export CERT_HTTP_PORT=8080
export XDG_DATA_HOME=/tmp/xds-ssl-test

echo "Configuration:"
echo "  SSL_ENABLE: $SSL_ENABLE"
echo "  SSL_STAGING: $SSL_STAGING (using Let's Encrypt staging)"
echo "  SSL_ACME_EMAIL: $SSL_ACME_EMAIL"
echo "  CERT_HTTP_PORT: $CERT_HTTP_PORT"
echo "  XDG_DATA_HOME: $XDG_DATA_HOME"
echo ""

# Create test directory
mkdir -p $XDG_DATA_HOME

# Start the XDS server with SSL config
echo "Starting XDS server with SSL support..."
echo "Using config: gateway-auth-ssl.yaml"
echo ""

# Run the server (will need actual domain pointing to this server for real test)
./xds-server -config gateway-auth-ssl.yaml -port 18000

# Note: For actual testing with Let's Encrypt:
# 1. You need a real domain pointing to this server
# 2. Port 80 (or configured CERT_HTTP_PORT) must be accessible from internet
# 3. Update the domain in gateway-auth-ssl.yaml to your actual domain