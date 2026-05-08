# Client `enabled` Toggle and `description` Field in Gateway YAML

## Overview

Two related additions to each entry in the `clients` array of the gateway YAML
config consumed by the xDS server:

1. **`enabled`** (bool, default `true`). When `false`, the xDS server skips that
   client entirely — Envoy receives no cluster, no route, and no per-cluster
   filter config for it. The YAML entry is preserved, allowing operators to
   keep historical client definitions in the file and toggle them back on
   quickly.
2. **`description`** (string, optional). Free-form text describing the client.
   Accepted by the YAML parser but otherwise unused — it never reaches Envoy
   or the filter. Purely operator-facing documentation that travels with the
   config.

**Problem solved:** Today, removing a client requires deleting (or commenting
out) its YAML block, which loses configuration history. `enabled: false` gives
operators a soft-disable that survives in the file. `description` lets
operators annotate why a client exists (or why it was disabled) without
relying on YAML comments that tooling may strip.

**Integration:** The change is contained to the xDS server (`xds/app/`). No
filter (`plugin/`) code change is required — disabled clients never reach the
filter because they are filtered out at xDS resource generation time, and
`description` is intentionally never serialised into filter config.
Documentation is updated in `xds/README.md` and `plugin/filter/llms.txt`.

## Context (from discovery)

- **files/components involved:**
  - `xds/app/config.go` — `ClientConfig` struct, `LoadConfig`, defaults loop
  - `xds/app/resources.go` — four iteration sites over `config.Clients`:
    - L168: per-cluster plugin config (sent to filter)
    - L338: TLS-domain collection for downstream TLS context
    - L422: route generation (`MakeRoutes`)
    - L555: cluster generation (`MakeClusters`)
  - `xds/app/ssl.go` — two iteration sites for ACME cert acquisition:
    - L72: `(*XDSServer).collectDomains()` (driven by `startHTTPChallenge`)
    - L209: `collectDomainsFrom(*GatewayConfig)` (driven by
      `handleSSLConfigChange` on YAML reload)
  - `xds/app/config_test.go`, `xds/app/resources_test.go` — existing patterns
  - `example/standalone/gateway-auth.yaml` — operator-facing example config
  - `xds/README.md` — client config table at L142–167
  - `plugin/filter/llms.txt` — operator config tables at section 10
- **related patterns found:**
  - Existing default-true bools (e.g. `OAuth.EnableBearerToken`) are set on the
    parent struct **before** `yaml.Unmarshal` (config.go:280–282). This trick
    only works for singletons, not for slice items.
  - Per-client post-unmarshal default loop already exists at config.go:341–348
    (defaults `Port` to 8080, `Prefix` to `/`).
  - `Exclude` is a different concept (skip auth, still route/cluster) — must
    not be conflated with `Enabled`.
- **dependencies identified:** `gopkg.in/yaml.v3` (already used). No new deps.

## Development Approach

- **testing approach:** Regular (code first, then tests in same task).
- complete each task fully before moving to the next.
- make small, focused changes.
- **CRITICAL: every task MUST include new/updated tests** for code changes.
  - tests are not optional — they are a required part of the checklist.
  - cover both success and error / edge scenarios.
- **CRITICAL: all tests must pass before starting the next task.**
- **CRITICAL: update this plan file when scope changes during implementation.**
- run tests after each change.
- maintain backward compatibility — existing configs without `enabled` must
  behave exactly as before (treated as enabled).

## Testing Strategy

- **unit tests** (Go `testing` package): required for every task.
  - `xds/app/config_test.go` — YAML unmarshal default (absent / `true` / `false`).
  - `xds/app/resources_test.go` — verify disabled clients are absent from
    routes, clusters, plugin config, and TLS-domain list.
- **e2e tests:** project does not have UI/Playwright e2e tests. The example
  docker-compose stacks are integration smoke tests; manual verification
  covered in Post-Completion.

## Progress Tracking

- mark completed items with `[x]` immediately when done.
- add newly discovered tasks with ➕ prefix.
- document issues/blockers with ⚠️ prefix.
- update plan if implementation deviates from original scope.
- keep plan in sync with actual work done.

## Solution Overview

1. **Schema:** Add `Enabled *bool` field (yaml tag `enabled,omitempty`) to
   `ClientConfig`. Pointer semantics — `nil` means "not specified" → treated as
   enabled. The `omitempty` tag keeps marshalled output clean for round-trips.
2. **Helper:** Add a method `func (c ClientConfig) IsEnabled() bool` returning
   `true` if `c.Enabled == nil || *c.Enabled`. Centralises the nil-safe check
   and prevents drift across all six iteration sites (four in `resources.go`,
   two in `ssl.go`). The doc comment on `IsEnabled` notes it is independent
   of `Exclude` (filter-level auth bypass) — disabling/enabling a client and
   excluding it from auth are orthogonal concerns.
3. **Filtering at xDS layer:** Every loop over `config.Clients` that emits
   Envoy-visible state skips entries where `IsEnabled()` is false. The full
   list of skip sites:
   - `resources.go` — plugin config map (~L168), TLS-domain pass for SDS
     (~L338), `MakeRoutes` (~L422), `MakeClusters` (~L555).
   - `ssl.go` — `(*XDSServer).collectDomains()` (~L72) and the pure
     `collectDomainsFrom(*GatewayConfig)` helper (~L209). Both feed Let's
     Encrypt cert acquisition; without the skip, a disabled client with
     `tls: true` would still trigger ACME challenges.
   The filter never sees disabled clients, so no filter changes are needed.
4. **Validation:** `LoadConfig` skips `id`/`address` required-field validation
   for disabled clients (same precedent as `Exclude` skipping the provider
   validation in `validateProviders`). This lets operators keep partially-
   populated historical entries. The defaults loop at config.go:341–348
   (`Port=8080`, `Prefix="/"`) **deliberately runs for all clients including
   disabled ones** — so re-enabling a client by flipping `enabled: true`
   produces a sane runtime config without further edits.
5. **`Description` field:** Add `Description string \`yaml:"description,omitempty"\``
   to `ClientConfig`. Free-form text. The struct field is read by `yaml.Unmarshal`
   and otherwise untouched — no validation, no propagation into Envoy or filter
   config. The `omitempty` tag keeps marshalled output clean when absent.
6. **Documentation:** Add `enabled` and `description` rows to the client table
   in `xds/README.md`, plus a short "Disabling clients" subsection with an
   example that also showcases `description`. Update
   `example/standalone/gateway-auth.yaml` to demonstrate both fields on real
   clients (annotate one with `description:`, show one commented `enabled:
   false` example). Add a brief operator-facing note in
   `plugin/filter/llms.txt` section 10.2 explaining that disabled clients are
   filtered at the gateway and never appear in `clusters`, and that
   `description` is gateway-only metadata not visible to the filter. Rebuild
   the filter so the embedded `llms.txt` reflects the change (`make build`).

### Why `*bool` over `disabled bool` or custom UnmarshalYAML

- User explicitly asked for `enabled` keyword (rules out `disabled` inverse).
- `*bool` is idiomatic Go for "optional with non-zero default" and avoids
  per-struct `UnmarshalYAML` boilerplate.
- Confined behind `IsEnabled()`, so callers never deal with the pointer.

## Technical Details

### Data structures

```go
// xds/app/config.go
type ClientConfig struct {
    ID          string `yaml:"id"`
    // ... existing fields ...
    Enabled     *bool  `yaml:"enabled,omitempty"`     // Default: true. Set to false to skip this client at xDS generation.
    Description string `yaml:"description,omitempty"` // Free-form operator note. Not propagated to Envoy or filter.
    // ... existing fields ...
}

// IsEnabled reports whether this client should be served by Envoy.
// A nil Enabled pointer (field absent in YAML) is treated as enabled.
func (c ClientConfig) IsEnabled() bool {
    return c.Enabled == nil || *c.Enabled
}
```

### YAML semantics

| YAML form              | `Enabled` value | `IsEnabled()` |
|------------------------|-----------------|---------------|
| (field absent)         | `nil`           | `true`        |
| `enabled: true`        | `*bool(true)`   | `true`        |
| `enabled: false`       | `*bool(false)`  | `false`       |

### Processing flow

```
LoadConfig:
  yaml.Unmarshal              — `enabled` populates Enabled pointer
  per-client defaults loop    — runs for ALL clients (deliberate)
  validation loop             — skip ID/Address checks if !IsEnabled()

MakeListener:
  for client in Clients:
    if !client.IsEnabled(): continue   ← new
    build per-cluster plugin config
  for client in Clients (TLS-domain pass):
    if !client.IsEnabled(): continue   ← new
    collect tls domain

MakeRoutes:
  for client in Clients:
    if !client.IsEnabled(): continue   ← new
    build route(s)

MakeClusters:
  for client in Clients:
    if !client.IsEnabled(): continue   ← new
    build cluster

ssl.go:
  collectDomains() / collectDomainsFrom(cfg):
    for client in Clients:
      if !client.IsEnabled(): continue   ← new
      collect domain for ACME
```

## What Goes Where

- **Implementation Steps** (`[ ]` checkboxes): code in `xds/app/`, tests, and
  documentation updates.
- **Post-Completion** (no checkboxes): manual smoke test with
  `make start` / `docker-compose` and verifying disabled clients return
  404 from Envoy.

## Implementation Steps

### Task 1: Add `Enabled` field and `IsEnabled` helper

**Files:**
- Modify: `xds/app/config.go`
- Modify: `xds/app/config_test.go`

- [x] add `Enabled *bool \`yaml:"enabled,omitempty"\`` to `ClientConfig` struct
      in `xds/app/config.go` (place near `Exclude` for grouping)
- [x] add `IsEnabled()` method on `ClientConfig` in same file, returning
      `c.Enabled == nil || *c.Enabled`
- [x] write table-driven unit test `TestClientConfigIsEnabled` in
      `xds/app/config_test.go` covering nil pointer, `*true`, `*false`
- [x] write YAML round-trip test asserting:
      - field absent → `IsEnabled()` is true
      - `enabled: true` → `IsEnabled()` is true
      - `enabled: false` → `IsEnabled()` is false
- [x] run `go test ./xds/app/...` — must pass before next task

### Task 2: Add optional `Description` field

**Files:**
- Modify: `xds/app/config.go`
- Modify: `xds/app/config_test.go`

- [x] add `Description string \`yaml:"description,omitempty"\`` to
      `ClientConfig` (place near `ID` / metadata fields, not near routing
      fields)
- [x] confirm no other code path references `Description` — it must remain a
      passive, parser-only field (no propagation into `MakeRoutes`,
      `MakeClusters`, `MakeListener`, or plugin config)
- [x] write `TestClientConfigDescription` covering:
      - YAML with `description: "legacy auth, kept for rollback"` round-trips
        to/from `ClientConfig.Description`
      - YAML without `description` produces empty string
      - `LoadConfig` accepts a config containing `description` without error
- [x] structurally assert `description` does not leak into filter config:
      in a resource test, build a config with `description: "..."` set on a
      client, call `MakeListener`, unmarshal the produced `anypb.Any` back
      to a `xdstype.TypedStruct`, and walk into `Value.Fields["clusters"]`
      → per-client `*structpb.Struct` → assert `Fields["description"]` is
      absent. Mirrors how the existing tests in `resources_test.go` inspect
      route/cluster output.
- [x] run `go test ./xds/app/...` — must pass before next task

### Task 3: Skip disabled clients in `LoadConfig` validation

**Files:**
- Modify: `xds/app/config.go`
- Modify: `xds/app/config_test.go`

- [x] in the per-client validation loop (config.go ~L352–359), add
      `if !client.IsEnabled() { continue }` before `id`/`address` required-field
      checks (mirrors how `validateProviders` skips excluded clients)
- [x] also skip disabled clients in `validateProviders` (config.go ~L164) so
      a disabled client may safely reference an undefined provider
- [x] **deliberately do NOT skip the per-client defaults loop at config.go
      :341–348** (`Port`, `Prefix`). Disabled clients still get sane defaults
      so flipping `enabled: true` requires no further edits. Add a one-line
      code comment above that loop explaining the intent.
- [x] write tests:
      - config with one disabled client missing `address` loads without error
      - config with one disabled client referencing undefined provider loads
        without error
      - config with one **enabled** client missing `address` still errors
      - **mixed case**: config with one disabled client (missing `address`)
        AND one enabled client (also missing `address`) → returns error,
        and the error message mentions the *enabled* client's ID (proves
        the disabled-client skip does not short-circuit further iteration)
- [x] run `go test ./xds/app/...` — must pass before next task

### Task 4: Skip disabled clients in `MakeRoutes`

**Files:**
- Modify: `xds/app/resources.go`
- Modify: `xds/app/resources_test.go`

- [x] in `MakeRoutes`, add `if !client.IsEnabled() { continue }` at the top of
      the `for _, client := range config.Clients` loop (resources.go:422)
- [x] write `TestMakeRoutesSkipsDisabledClients`:
      - config has two clients: one `enabled: nil` (default), one
        `enabled: false`
      - assert resulting routes contain only the enabled cluster
      - assert disabled cluster's domain does NOT appear as a virtual host
- [x] run `go test ./xds/app/...` — must pass before next task

### Task 5: Skip disabled clients in `MakeClusters`

**Files:**
- Modify: `xds/app/resources.go`
- Modify: `xds/app/resources_test.go`

- [x] in `MakeClusters`, add `if !client.IsEnabled() { continue }` at the top
      of the loop (resources.go:555)
- [x] write `TestMakeClustersSkipsDisabledClients` asserting:
      - one disabled + one enabled client → exactly one cluster resource
      - cluster name matches the enabled client's ID
- [x] run `go test ./xds/app/...` — must pass before next task

### Task 6: Skip disabled clients in plugin config and TLS-domain pass

**Files:**
- Modify: `xds/app/resources.go`
- Modify: `xds/app/resources_test.go`

- [x] in the per-cluster plugin-config loop (resources.go:168), add
      `if !client.IsEnabled() { continue }` so disabled clients don't appear in
      `clusters` map sent to the filter
- [x] in the TLS-domain collection loop (resources.go:338), add
      `if !client.IsEnabled() { continue }` so a disabled client with
      `tls: true` doesn't trigger SDS certificate provisioning
- [x] write `TestMakeListenerSkipsDisabledClientsFromPluginConfig`:
      - assert the serialized plugin `clusters` map omits disabled client IDs
- [x] write `TestMakeListenerSkipsDisabledClientsFromTLSDomains`:
      - config with two clients, both `tls: true, domain: ...`, one disabled
      - assert only the enabled client's domain ends up in the SDS configs
- [x] run `go test ./xds/app/...` — must pass before next task

### Task 7: Skip disabled clients in `ssl.go` cert-acquisition paths

**Files:**
- Modify: `xds/app/ssl.go`
- Modify: `xds/app/ssl_test.go` (create if absent)

- [x] in `(*XDSServer).collectDomains()` at ssl.go:72, add
      `if !client.IsEnabled() { continue }` before the `client.TLS &&
      client.Domain != ""` check so disabled TLS clients do not trigger ACME
      challenges
- [x] in `collectDomainsFrom(cfg)` at ssl.go:209, add the same guard so
      `handleSSLConfigChange` (called on YAML reload) does not request certs
      for newly-disabled clients
- [x] write `TestCollectDomainsFromSkipsDisabledClients`:
      - config with two clients, both `tls: true, domain: ...`, one disabled
      - assert returned slice contains only the enabled client's domain
- [x] no test for `(*XDSServer).collectDomains()` is required if it just
      wraps `s.config.Clients` with the same logic — covered by review of
      both call sites being identical. If they diverge, add a parallel test
      for the method. (Added `TestCollectDomainsSkipsDisabledClients` for
      symmetry / future safety.)
- [x] run `go test ./xds/app/...` — must pass before next task

### Task 8: Update `xds/README.md` and example config

**Files:**
- Modify: `xds/README.md`
- Modify: `example/standalone/gateway-auth.yaml`

- [x] add `enabled` row to the client config table (~L146–167):
      `| \`enabled\` | No | \`true\` | Set to \`false\` to keep the client entry in YAML history but skip it during xDS generation (no cluster, no route, no filter config) |`
- [x] add `description` row to the same table:
      `| \`description\` | No | - | Free-form text describing this client. Operator-facing only — not sent to Envoy or the filter |`
- [x] add a short "Disabling Clients" subsection after "Multi-Domain Routing
      Example" with a worked example that also showcases `description`:
      ```yaml
      clients:
        - id: legacy_api
          description: "v1 of the auth API; kept for rollback during the v2 migration"
          address: legacy-backend
          port: 8080
          domain: "legacy.example.com"
          enabled: false   # kept for history; Envoy ignores this client
      ```
- [x] in `example/standalone/gateway-auth.yaml`, annotate one existing client
      with a real `description:` line, and add one commented-out
      `# enabled: false` example so operators copy-pasting the standalone
      example see the new fields in context. Keep all clients functionally
      enabled (no behaviour change to the example stack).
- [x] no tests required for documentation/example changes

### Task 9: Update `/oauth/llms.txt` operator docs and rebuild filter

**Files:**
- Modify: `plugin/filter/llms.txt`
- Modify: `plugin/filter/llms_test.go` (if assertion needs updating)

- [x] in section 10.2 (`ClusterConfig`), add a two-line operator note below
      the table:
      - "Operators may set `enabled: false` on a client in the gateway YAML;
        such clients are filtered out at the xDS layer and never appear in the
        `clusters` map below."
      - "The gateway YAML also accepts a free-form `description` string per
        client. It is operator-facing metadata only and is not propagated into
        the filter config."
- [x] update `llms_test.go` only if it asserts on a string that we change;
      otherwise leave as-is (the embed test just checks non-empty) — left as-is, existing tests still pass
- [x] run `go test ./plugin/filter/...` — must pass before next task
- [x] note: the embedded copy is rebuilt via `go:embed` on next `make build`;
      no manual rebuild needed for unit tests

### Task 10: Verify acceptance criteria

- [x] verify all requirements from Overview are implemented:
      - `enabled` field exists in YAML schema (xds/app/config.go:85)
      - default is `true` (absent field treated as enabled — `IsEnabled()` at config.go:105)
      - disabled clients produce no Envoy cluster, route, TLS cert, or filter
        config (skip sites at resources.go:171, 346, 433, 569 and ssl.go:74, 216)
      - `description` field is accepted by the parser, does not affect Envoy
        behaviour, and is not present in serialised filter config (config.go:77)
      - documented in `xds/README.md` (rows added at L149-150, "Disabling Clients" subsection) and `plugin/filter/llms.txt` (operator notes at L538-540)
- [x] run full test suite: `go test ./...` — both modules pass (plugin/... and xds/app passed cleanly with -count=1; flaky `TestMakeRoutesWithDomains` passed on first attempt)
- [x] run `make build` to confirm the project still compiles — [x] manual test (skipped - Docker not available in this environment); verified compilation directly with `go build -buildmode=c-shared ./plugin/libgolang/` which produced a 20MB .so file successfully, plus `go vet ./...` and `cd xds && go vet ./...` both clean
- [x] run `golangci-lint run ./...` (project lint config) — no project lint config exists; ran with default config on both modules. All issues found (10 in plugin, 17 in xds) are pre-existing and unrelated to `enabled`/`description` changes (errcheck on `resp.Body.Close`, `os.Setenv` in tests, etc.)

### Task 11: Final — Update documentation index and move plan

- [x] update `CLAUDE.md` only if a new pattern emerged (likely not — pure
      schema addition) — no new pattern; CLAUDE.md unchanged
- [x] `mkdir -p docs/plans/completed`
- [x] move this plan to `docs/plans/completed/20260508-client-enabled-toggle.md`

## Post-Completion

*Items requiring manual intervention or external systems — informational only.*

**Manual verification:**
- Start the example stack: `make start`.
- Confirm two clients in `gateway-auth.yaml`, set `enabled: false` on one.
- Send requests:
  - Enabled client domain → 200 / OAuth redirect (normal flow).
  - Disabled client domain → 404 from Envoy (no virtual host matches).
- Toggle `enabled: true`, send SIGHUP / let xDS reload, verify the disabled
  client is reachable again without restart.

**External system updates:**
- None. This is an internal gateway YAML schema addition. No consuming
  projects, no third-party integrations.
- Operators with existing configs need no migration — `enabled` defaults to
  `true` when absent, and `description` is optional with no default.
