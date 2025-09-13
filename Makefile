.PHONY: build test run start clean release

VERSION ?= $(shell grep -m1 "Version =" plugin/filter/version.go | cut -d '"' -f2)
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -X main.GitCommit=$(GIT_COMMIT) -X main.BuildDate=$(BUILD_DATE)

build:
	docker build -t go-envoy-oauth-builder . && docker run --rm -v "$$PWD/dist:/output" go-envoy-oauth-builder

test:
	go test -v ./plugin/...

test-coverage:
	go test -v -coverprofile=coverage.out ./plugin/...
	go tool cover -html=coverage.out -o coverage.html

run:
	cd example/standalone; docker compose up

start:
	cd example/standalone; docker compose up -d

clean:
	rm -rf dist
	rm -f coverage.out coverage.html

# Create a GitHub release - requires VERSION argument
release:
	@echo "Creating release v$(VERSION)"
	@git tag -a v$(VERSION) -m "Release v$(VERSION)"
	@echo "Tagged v$(VERSION)"
	@echo "Run 'git push origin v$(VERSION)' to push the tag to GitHub"

# Build the project locally without Docker
build-local:
	go build -ldflags "$(LDFLAGS)" -o dist/go-envoy-oauth.so -buildmode=c-shared ./plugin/libgolang
