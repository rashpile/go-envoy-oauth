# Build stage
FROM golang:1.23.6-bookworm AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files to leverage Docker's cache mechanism
COPY go.mod go.sum ./

# Download dependencies only if go.mod and go.sum have changed
RUN go mod download

# Copy the Go project files into the container
COPY . .

# Set the GOFLAGS environment variable to disable VCS stamping
ENV GOFLAGS=-buildvcs=false

# Build the Go project with c-shared mode to produce a shared object file
RUN go build -o /output/go-envoy-oauth.so -buildmode=c-shared ./plugin/libgolang

# Final stage
FROM alpine:3.19

# Label the image with standard OCI annotations
LABEL org.opencontainers.image.source="https://github.com/rashpile/go-envoy-oauth"
LABEL org.opencontainers.image.description="OAuth authentication filter for Envoy Proxy"
LABEL org.opencontainers.image.licenses="MIT"

# Copy only the built .so file from the builder stage
COPY --from=builder /output/go-envoy-oauth.so /go-envoy-oauth.so

COPY scripts/extract.sh ./
# Create an entrypoint script for file extraction
RUN chmod +x /extract.sh

# Set the entrypoint to the extraction script
ENTRYPOINT ["/extract.sh"]

# This container can be used in two ways:
# 1. As a source for the .so file in Envoy (mount the .so file directly)
# 2. For extraction of the .so file (run with a volume mount to copy the file out)
