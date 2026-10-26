# go-envoy-oauth review profile

## What this software is

- An Envoy Go HTTP filter (`plugin/`, built as a C-shared `.so`) that authenticates every request at an API gateway: OAuth 2.0/OIDC login, session cookies, bearer JWTs, offline-token API keys, per-cluster `allowed_users`.
- A separate xDS control-plane module (`xds/`, its own `go.mod`) that turns operator YAML (`gateway-auth.yaml`) into Envoy listeners, routes, clusters and the per-cluster filter config.
- Production: one gateway in front of every domain on a host. Single maintainer, self-hosted Keycloak.

## What a real failure looks like

- **Auth bypass** — a request reaches an upstream without valid credentials, or with identity headers (`X-User-*`, `X-Auth-Provider`) the client supplied.
- **Wrong identity** — a token, session or API key for one user, client, audience or provider accepted as another.
- **Open redirect / host trust** — URLs or cookie domains built from client-controlled headers.
- **Lockout** — valid users or whole domains get 401/403/503 after a release.
- **Config drift** — a key xDS emits that the filter drops (e.g. a `ClusterConfig` field missed in one of the hand-written `Merge` copies), or validation that differs between the two modules.

## Blast radius

- The filter runs for every domain on the host; a decode-path regression breaks unrelated services.
- Filter and xDS ship together; the filter ignores unknown keys, so a mismatch fails open to the previous behavior rather than erroring.

## Reporting bar

- Report: anything above, missing tests for a new auth branch, behavior change on paths outside the change.
- Do not report: style the linter owns (`gofmt`, `goimports`, golangci-lint v1.56.2), naming taste, missing godoc on unexported helpers, hypothetical providers other than Keycloak unless the code claims generality.

## Deliberate conventions

- `plugin/` and `xds/` must not import each other; parallel structs and duplicated validation across them are intentional.
- Default-deny authorization: `isUserPermitted` denies when no `allowed_users` matches.
- Fail closed on ambiguous paths (`hasAmbiguousSegments`): exclusions never match them.
- Alternate auth paths live in their own file (`websocket.go`, `llms.go`, `mcp.go`); pure reply functions (`llmsTxtReply`) are tested without SDK mocks.
- Metrics use the `envoy_oauth_` prefix; the `idp` label is the provider registry key.
- `docs/plans/` is gitignored on purpose.
- Security fixes reference Gitea issue numbers in comments (`issue #8`).
