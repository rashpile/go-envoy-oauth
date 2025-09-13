# Build stage
FROM golang:1.23.6-bookworm AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files to leverage Docker's cache mechanism
COPY go.mod go.sum ./

# Download dependencies only if go.mod and go.sum have changed
RUN go mod download

# Copy the Go project files into the container
COPY app/ ./app/

# Set the GOFLAGS environment variable to disable VCS stamping
ENV GOFLAGS=-buildvcs=false

# Build the XDS server binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /output/xds-server ./app

# Final stage
FROM alpine:3.19

# Label the image with standard OCI annotations
LABEL org.opencontainers.image.source="https://github.com/rashpile/go-envoy-oauth"
LABEL org.opencontainers.image.description="XDS control plane server for go-envoy-oauth"
LABEL org.opencontainers.image.licenses="MIT"

# Install ca-certificates for HTTPS support
RUN apk --no-cache add ca-certificates

# Copy only the built binary from the builder stage
COPY --from=builder /output/xds-server /xds-server

# Copy envoy-xds.yaml configuration file
COPY envoy-xds.yaml /envoy-xds.yaml

# Create extraction script
RUN echo '#!/bin/sh' > /extract.sh && \
    echo 'if [ -d /output ]; then' >> /extract.sh && \
    echo '  cp /xds-server /output/' >> /extract.sh && \
    echo '  cp /envoy-xds.yaml /output/' >> /extract.sh && \
    echo '  echo "Copied xds-server and envoy-xds.yaml to /output directory"' >> /extract.sh && \
    echo 'else' >> /extract.sh && \
    echo '  echo "No output directory mounted. Run with -v /path/on/host:/output to extract the files."' >> /extract.sh && \
    echo '  echo "Example: docker run --rm -v \$(pwd)/dist:/output ghcr.io/rashpile/go-envoy-xds:latest"' >> /extract.sh && \
    echo 'fi' >> /extract.sh && \
    chmod +x /extract.sh

# Set the entrypoint to the extraction script
ENTRYPOINT ["/extract.sh"]

# This container can be used in two ways:
# 1. For extraction of the xds-server binary (run with a volume mount to copy the file out)
# 2. Override entrypoint to run the server directly