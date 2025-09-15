/app/xds-server --config=/app/gateway-auth.yaml --port=18000 > /tmp/xds-server.log 2>&1 &
envoy -c /etc/envoy/envoy.yaml
