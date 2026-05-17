.PHONY: help build test run start clean release build-standalone build-xds build-local test-coverage stop logs

.DEFAULT_GOAL := help

VERSION ?= $(shell grep -m1 "Version =" plugin/filter/version.go | cut -d '"' -f2)
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -X main.GitCommit=$(GIT_COMMIT) -X main.BuildDate=$(BUILD_DATE)
IMAGE_TAG ?= latest
IMAGE_NAME ?= go-envoy-oauth

help: ## Show this help message
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

build: ## Build OAuth filter .so via Docker
	docker build -t go-envoy-oauth-builder . && docker run --rm -v "$$PWD/dist:/output" go-envoy-oauth-builder

build-xds: ## Build xDS control-plane server via Docker
	cd xds && docker build -t go-envoy-xds-builder . && docker run --rm -v "$$PWD/../dist:/output" go-envoy-xds-builder

build-standalone: ## Build standalone Envoy image with OAuth plugin and xDS server
	@echo "Building standalone Envoy image with OAuth plugin..."
	docker build -f Dockerfile-envoy -t $(IMAGE_NAME):$(IMAGE_TAG) .
	@echo "Successfully built $(IMAGE_NAME):$(IMAGE_TAG)"
	@echo ""
	@echo "To run the standalone image:"
	@echo "  docker run -p 8080:8080 -p 9901:9901 \\"
	@echo "    -e OAUTH_ISSUERURL=<your-issuer-url> \\"
	@echo "    -e OAUTH_CLIENTID=<your-client-id> \\"
	@echo "    -e OAUTH_CLIENTSECRET=<your-client-secret> \\"
	@echo "    $(IMAGE_NAME):$(IMAGE_TAG)"

test: ## Run plugin tests
	go test -v ./plugin/...

test-coverage: ## Run tests and generate HTML coverage report
	go test -v -coverprofile=coverage.out ./plugin/...
	go tool cover -html=coverage.out -o coverage.html

run: ## Run standalone example in foreground (docker compose up)
	cd example/standalone; docker compose up

start: ## Start standalone example in background
	cd example/standalone; docker compose up -d

stop: ## Stop standalone example
	cd example/standalone; docker compose down

logs: ## Tail logs from standalone example
	cd example/standalone; docker compose logs

clean: ## Remove build artifacts and coverage files
	rm -rf dist
	rm -f coverage.out coverage.html

release: ## Tag a GitHub release using VERSION from version.go
	@echo "Creating release v$(VERSION)"
	@git tag -a v$(VERSION) -m "Release v$(VERSION)"
	@echo "Tagged v$(VERSION)"
	@echo "Run 'git push origin v$(VERSION)' to push the tag to GitHub"

build-local: ## Build the filter .so locally (no Docker)
	go build -ldflags "$(LDFLAGS)" -o dist/go-envoy-oauth.so -buildmode=c-shared ./plugin/libgolang
