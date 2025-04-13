#!/bin/sh

if [ -d /output ]; then
  cp /go-envoy-oauth.so /output/
  echo "Copied go-envoy-oauth.so to /output directory"
else
  echo "No output directory mounted. Run with -v /path/on/host:/output to extract the .so file."
  echo "Example: docker run --rm -v \$(pwd)/dist:/output ghcr.io/rashpile/go-envoy-oauth:latest"
fi
