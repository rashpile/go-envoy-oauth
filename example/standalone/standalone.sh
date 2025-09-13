/app/xds-server --config=/app/gateway-auth.yaml --port=18000 &
envoy -c /etc/envoy/envoy.yaml
