# Replace `super_users` with provider-scoped `allowed_users`

## Overview

Remove the global `super_users` config field. Add an `allowed_users` field to each entry in the `providers:` registry. Authorization in `Filter.isUserPermitted()` checks the provider's `allowed_users` first (OR-grant — match here permits immediately, including across clusters with no `Clusters[]` entry). If no match, fall through to the existing `cluster.allowed_users` check. Default-deny semantics are preserved.

This is a coordinated two-module change: `xds/` (producer) generates the plugin config that `plugin/` (consumer) parses. Both must ship together because the plugin tolerates unknown YAML keys — an in-flight upgrade where xds still emits `super_users:` but the new plugin no longer reads it would silently change access.

Problem solved: today, `super_users` is a global blanket-bypass with no scoping. Provider-scoped `allowed_users` gives operators a finer-grained "trusted across this IdP's clusters" grant while keeping the cluster-level fence as the narrow check.

### Intentional behavior changes (locked in brainstorm, called out for reviewers)

1. **Silent breaking change for legacy `super_users:` configs.** Per brainstorm decision, removal is hard — no deprecation log, no warning. Operators still shipping `super_users:` in YAML get silent privilege revocation. Risks section below covers operator communication.
2. **Provider grant reaches clusters with no `Clusters[]` entry.** The OR-grant runs before the `f.config.Clusters[f.cluster]` lookup, so a provider-listed user can hit unconfigured clusters routed through this filter (mirrors old super_users reach, scoped to the provider).
3. **Audit log fires more often.** The "permission granted" audit log at filter.go:218-219 currently triggers only when `cluster.AllowedUsers` is non-empty. It now also triggers when `provider.AllowedUsers` is non-empty. Deployments using only provider-level allow will see new audit log volume.

## Context (from discovery)

- **Plugin module** (`plugin/filter/`): consumes the YAML emitted as Envoy `typed_per_filter_config`. Key files: `parser.go` (struct + parse), `filter.go` (`isUserPermitted` at line 912, `resolveProviderName` at line 108, audit-log at line 218-219).
- **xds module** (`xds/app/`): standalone control-plane server that produces the plugin config. Key files: `config.go` (operator-facing schema), `resources.go` (serializes into the structpb payload).
- **Existing patterns reused**:
  - Cluster-level `AllowedUsers` parse loop at `plugin/filter/parser.go:386-392` — provider-level parse mirrors this.
  - Cluster-level wildcard `*` handling at `plugin/filter/filter.go:941` — provider-level uses identical loop body.
  - Cluster-level serialization at `xds/app/resources.go:211-217` — provider-level serialization mirrors this.
  - `resolveProviderName()` at `plugin/filter/filter.go:108` is already used by the encode-headers path; authorization reuses it.
- **Documentation files referencing `super_users`** (must update; grep-confirmed):
  - `plugin/filter/llms.txt:523` — agent-integration doc surfaced by the `/oauth/llms.txt` endpoint.
  - `README.md:186` — repo root README (the `allowed_users` row references super_users in its description).
  - `xds/README.md:162` — xds operator README (same shape).
  - `docs/superpowers/plans/2026-05-04-oauth-llms-txt.md:736` — historical completed plan; leave as-is (frozen artifact).
- **No xds tests reference `SuperUsers`** (grep confirmed).
- **No checked-in YAML files use `super_users:`** — operator YAML migration is a no-op for this repo, but production deployments may still ship it.

## Development Approach

- **Testing approach**: Regular (code first, then tests in the same task — matches existing project pattern in `filter_test.go`).
- Complete each task fully before moving to the next.
- **Each task MUST leave the tree compiling** — `go build ./...` from both module roots must succeed at every task boundary. Where a schema change and its dependent parser/serializer changes must move atomically to stay compilable, they live in one task (see Tasks 1 and 4).
- **CRITICAL: every code task MUST include new/updated tests for the changes in that task.**
  - Tests are required, not optional.
  - Cover both success and failure branches (permit + deny).
  - For removed code (`super_users` paths), update the existing tests that previously relied on it.
- **CRITICAL: all tests must pass before starting next task** — `go test ./...` from each module root.
- Run tests after each change.
- Maintain default-deny semantics throughout.

## Testing Strategy

- **Unit tests**: required for every code task. Both modules have established unit-test patterns (`plugin/filter/*_test.go`, `xds/app/*_test.go`).
- **No e2e tests in this repo** — the project uses unit tests + the example docker-compose setups for manual verification. No e2e suite to update.
- **Build verification**: each module compiles independently; CI exercises both. Run `make build` for the plugin shared object and `go build ./...` from `xds/` for the xds binary as part of the verification task.

## Progress Tracking

- Mark completed items with `[x]` immediately when done.
- Add newly discovered tasks with ➕ prefix.
- Document issues/blockers with ⚠️ prefix.
- Update plan if implementation deviates from original scope.

## Solution Overview

**Direct refactor (Option A from brainstorm).** Extend `ProviderConfig` (both modules), add a parse/serialize branch for `allowed_users`, rewrite `isUserPermitted()` to check provider first then cluster, delete all `super_users` paths. No new types, no new files, no abstraction.

**Decisions locked in brainstorm:**
- Combination semantic: **OR** (provider match → permit; else cluster check; else deny).
- Empty/missing `provider.allowed_users` → skip provider check, defer to cluster.
- Wildcard `*` supported at both provider and cluster level.
- Migration: **hard remove** super_users — silently ignored if present (no warning log, no deprecation cycle).
- No new parse-time validation.
- Normalization: lowercase + trim + skip empty entries (mirror cluster pattern).

**Out of scope** (do not implement):
- New Prometheus metrics for authorization events.
- An `AuthRules` abstraction type.
- A deprecation warning for legacy `super_users:`.
- Per-route override path for `provider.allowed_users` (providers have no child-merge path today; preserve that).

## Technical Details

**Plugin authorization flow (new `isUserPermitted`):**

```
username := lower(session.Claims["preferred_username"])
if username == "" → deny

providerName := f.resolveProviderName()                 // existing helper, filter.go:108
if providerName != "" && provider exists in Providers:
    for each allowed in provider.AllowedUsers:
        if allowed == "*" || allowed == username → permit

clusterConfig, ok := f.config.Clusters[f.cluster]
if !ok → deny
for each allowed in clusterConfig.AllowedUsers:
    if allowed == "*" || allowed == username → permit

deny (with debug-level structured log)
```

**Audit log condition (filter.go:218-219)** extends to fire when either list is non-empty:
```go
hasProviderList := false
if pn := f.resolveProviderName(); pn != "" {
    if p, ok := f.config.Providers[pn]; ok && len(p.AllowedUsers) > 0 {
        hasProviderList = true
    }
}
clusterConfig, clusterExists := f.config.Clusters[f.cluster]
if hasProviderList || (clusterExists && len(clusterConfig.AllowedUsers) > 0) {
    // emit existing audit log
}
```

**YAML shape (after the change):**
```yaml
providers:
  keycloak:
    issuer_url: ...
    client_id: ...
    allowed_users:        # NEW — OR-grant at provider scope
      - alice
      - "*"               # wildcard supported
clusters:
  admin-api:
    provider: keycloak
    allowed_users:        # existing — fallback narrow check
      - charlie
# top-level `super_users:` removed (silently ignored if present)
```

## What Goes Where

- **Implementation Steps** (checkboxes): all code changes in `plugin/` and `xds/`, plus doc updates in `xds/README.md`, root `README.md`, and `plugin/filter/llms.txt`.
- **Post-Completion** (no checkboxes): operator YAML rotation in any non-repo deployment manifests (the repo's own YAML files are clean per discovery), and the coordinated release of plugin + xds binaries.

## Implementation Steps

### Task 1: Plugin — schema + parser (atomic: struct + parse + clone + merge)

Atomic because deleting `OAuthConfig.SuperUsers` breaks the parse/clone/merge references at the same instant; they must move together to keep the tree compiling at the task boundary.

**Files:**
- Modify: `plugin/filter/parser.go`
- Modify: `plugin/filter/parser_test.go`

- [x] At `parser.go:25-31`, add `AllowedUsers []string` field to `ProviderConfig` struct (after `Scopes`).
- [x] At `parser.go:93`, delete the `SuperUsers []string \`json:"super_users"\`` field from `OAuthConfig`.
- [x] At `parser.go:301-310`, delete the entire `super_users` parse branch (including the `log.Printf("Parsed super_users…")` line).
- [x] At `parser.go:556`, remove `SuperUsers: slices.Clone(parentConfig.SuperUsers),` from the parent→child clone block.
- [x] At `parser.go:641-643`, remove the `if len(childConfig.SuperUsers) > 0 { newConfig.SuperUsers = slices.Clone(childConfig.SuperUsers) }` block.
- [x] Inside the providers parse loop at `parser.go:313-341` (in the per-provider decoding block, after the `scopes` branch), add an `allowed_users` parse branch that mirrors `parser.go:386-392`: lowercase + trim each string entry, skip non-string entries silently, skip empty results, populate `pc.AllowedUsers`.
- [x] Run `go build ./...` from repo root — must compile cleanly.
- [x] In `parser_test.go`, add `TestParseProviderAllowedUsers` that decodes a `providers:` YAML block containing `allowed_users: ["Alice", "  ", "BOB", "alice"]` for one provider; assert `Providers["name"].AllowedUsers` is `["alice", "bob", "alice"]` (lowercased, trimmed, empties dropped; dedup is NOT performed — mirroring cluster behavior).
- [x] In `parser_test.go`, add `TestParseProviderAllowedUsersEmpty` that decodes a provider with no `allowed_users` key set; assert `Providers["name"].AllowedUsers` is `nil` (not an empty slice) and decode does not panic.
- [x] In `parser_test.go`, add `TestParseProviderAllowedUsersNonStringEntries` covering mixed types: `allowed_users: ["alice", 123, true, "bob"]`; assert non-string entries are skipped silently and `AllowedUsers` is `["alice", "bob"]`. Documents defensive parsing.
- [x] Run `go test ./plugin/filter/...` — all parser tests must pass before next task.

### Task 2: Plugin — rewrite `isUserPermitted` and extend audit log

**Files:**
- Modify: `plugin/filter/filter.go`

- [x] At `filter.go:909-948`, rewrite `isUserPermitted` per the Technical Details flow above. Reuse `resolveProviderName()` (already at filter.go:108). Update the function-level comment (currently at filter.go:910 — explicitly mentions `super_users`) to reflect the new provider-then-cluster check order. Default-deny preserved.
- [x] In the deny path of `isUserPermitted` (just before `return false`), add one debug-level structured log: `f.logger.Debug("authorization denied", zap.String("username", username), zap.String("provider_name", providerName), zap.String("cluster", f.cluster), zap.Int("provider_allowed_count", lenP), zap.Int("cluster_allowed_count", lenC))`. **PII guarantee: do NOT log the list contents themselves** — usernames are PII; only counts.
- [x] At `filter.go:218-219`, extend the audit-log condition to also fire when the resolved provider has a non-empty `AllowedUsers` list. Pattern shown in Technical Details. Keep the existing log message and fields.
- [x] Run `go build ./plugin/...` — must compile cleanly.
- [x] Tests for this task are added in Task 3 (they belong to `filter_test.go` and need the new permission branches in place).

### Task 3: Plugin — convert existing super_users tests and add new authorization + log tests

**Files:**
- Modify: `plugin/filter/filter_test.go`

- [ ] Convert the four `SuperUsers: []string{...}` literals at `filter_test.go:324, 362, 405, 457` to use `Providers: map[string]ProviderConfig{"test-provider": {AllowedUsers: []string{...}}}` plus a matching `Clusters[clusterName].ProviderName = "test-provider"`. Use a single shared provider-name constant if it improves readability.
- [ ] Add `TestProviderAllowGrantsWhenClusterDenies` — user in `provider.allowed_users`, NOT in `cluster.allowed_users`, cluster entry exists → permit. Proves OR-grant.
- [ ] Add `TestProviderWildcardAllow` — `provider.allowed_users: ["*"]`, user listed nowhere else → permit.
- [ ] Add `TestProviderAllowGrantsForClusterWithoutEntry` — user in `provider.allowed_users`, `f.cluster` is NOT a key in `f.config.Clusters` → permit. Documents the intentional widened-reach behavior called out in Overview.
- [ ] Add `TestEmptyProviderListDefersToCluster` — `provider.AllowedUsers: nil`, user in `cluster.allowed_users` → permit.
- [ ] Add `TestBothListsMissDenies` — user in neither list → deny.
- [ ] Add `TestUnknownProviderSkipsProviderCheck` — cluster's `ProviderName: "nonexistent"`, user in `cluster.allowed_users` → permit (provider lookup misses silently, cluster check still runs).
- [ ] Add `TestClusterWildcardStillWorks` — provider absent/empty, `cluster.allowed_users: ["*"]` → permit. Confirms cluster-level wildcard wasn't regressed.
- [ ] Add `TestAuditLogFiresWithProviderOnlyAllow` — using a captured zap logger (`zap/zaptest/observer`), permit a user via `provider.allowed_users` with `cluster.AllowedUsers` empty; assert the existing "permission granted" audit log entry fired. Covers the audit-log condition change at filter.go:218-219.
- [ ] Add `TestDenyLogOmitsListContents` — using the observer, trigger a deny path with non-empty `provider.AllowedUsers` and `cluster.AllowedUsers`; assert the debug log fires with `provider_allowed_count` / `cluster_allowed_count` fields and assert NO field contains the literal allowed-user strings. Locks in the PII guarantee.
- [ ] Run `go test ./plugin/filter/...` — all tests must pass before next task.
- [ ] Run `go vet ./plugin/...` — must be clean.

### Task 4: xds — schema + serializer (atomic: struct + serialize + delete super_users)

Atomic for the same reason as Task 1: deleting `GatewayConfig.SuperUsers` breaks the serializer reference at `resources.go:158`.

**Files:**
- Modify: `xds/app/config.go`
- Modify: `xds/app/resources.go`
- Modify: `xds/app/resources_test.go`

- [ ] At `config.go:19-25`, add `AllowedUsers []string \`yaml:"allowed_users,omitempty"\` // Provider-scoped OR-grant (matched against preferred_username, case-insensitive)` to `ProviderConfig`.
- [ ] At `config.go:36`, delete the entire `SuperUsers []string` field line from `GatewayConfig`.
- [ ] At `resources.go:157-164`, delete the entire `super_users` serialization block (the `if len(config.SuperUsers) > 0 { ... pluginConfig["super_users"] = ... }` stanza, including the `// Add global super_users to plugin config` comment).
- [ ] Inside the providers serialization loop at `resources.go:231-247`, after the `scopes` block, add an `if len(p.AllowedUsers) > 0` block that lowercases each entry and writes `providerMap["allowed_users"]`. Mirror the pattern at `resources.go:211-217`.
- [ ] Run `cd xds && go build ./...` — must compile cleanly.
- [ ] In `resources_test.go`, add `TestProviderAllowedUsersSerialization`: build a `GatewayConfig` with `Providers["kc"] = ProviderConfig{IssuerURL: "...", ClientID: "x", ClientSecret: "y", AllowedUsers: ["Alice", "BOB"]}`, invoke `createHTTPConnectionManager`, decode the resulting `TypedStruct` payload, assert `providers.kc.allowed_users` equals `["alice", "bob"]`.
- [ ] In `resources_test.go`, add `TestProviderAllowedUsersOmittedWhenEmpty`: build a `GatewayConfig` whose providers have no `AllowedUsers` set; assert the decoded `providers.<name>` map has NO `allowed_users` key (omitted, not empty).
- [ ] Run `cd xds && go test ./...` — all xds tests must pass before next task.

### Task 5: Update operator-facing documentation

**Files:**
- Modify: `xds/README.md`
- Modify: `README.md` (repo root)
- Modify: `plugin/filter/llms.txt`

- [ ] In `xds/README.md:162`, update the `allowed_users` row description from "If empty and the user is not in `super_users`, access is denied." to "If empty, the user must match the resolved provider's `allowed_users` to be permitted, otherwise access is denied."
- [ ] In `README.md:186`, apply the same wording fix to the `allowed_users` row.
- [ ] In `plugin/filter/llms.txt:523`, **delete the `super_users` row entirely** (it is part of the top-level config schema table and no longer exists as a config field).
- [ ] In `plugin/filter/llms.txt`, locate the `ProviderConfig` section (search for a `ProviderConfig` schema table around the providers documentation). Add a new row: `| \`allowed_users\` | string[] | empty | Lowercased usernames or emails granted access to all clusters served by this provider (OR-grant). Use \`["*"]\` to permit any authenticated user from this provider. |`
- [ ] In `xds/README.md` and `README.md`, search for any remaining mentions of `super_users` in either README (top-level config schema sections, examples, or migration notes). Each one: either delete (if it's an example) or replace with a `providers.<name>.allowed_users` equivalent (if it's a feature description).
- [ ] Repo-wide grep sanity: `grep -rn "super_users\|SuperUsers" plugin/ xds/ README.md CLAUDE.md` should now return zero hits, except inside `docs/superpowers/plans/` (frozen historical artifacts — leave alone).
- [ ] No tests in this task (docs only).

### Task 6: Verify acceptance criteria

- [ ] Verify all decisions from Overview are implemented:
  - [ ] `super_users` field removed from both modules.
  - [ ] `ProviderConfig.AllowedUsers` exists in both modules.
  - [ ] Provider check runs before cluster check in `isUserPermitted`.
  - [ ] Wildcard `*` works at both levels.
  - [ ] Empty/missing provider list falls through to cluster check.
  - [ ] xds serializes `provider.allowed_users` into the plugin config.
  - [ ] Audit log fires on provider-only allow.
  - [ ] Deny log never includes list contents.
- [ ] Run full plugin tests: `make test` from repo root.
- [ ] Run full xds tests: `cd xds && go test ./...`.
- [ ] Run plugin build: `make build` (Docker shared-object build).
- [ ] Run xds build: `cd xds && go build ./...`.
- [ ] **Release gate**: do NOT cut a release tag until both module artifacts are built from the same commit (avoid mixed-version deployments — see Risks).
- [ ] Final grep sanity check: `grep -rn "super_users\|SuperUsers" plugin/ xds/app/` returns zero hits.

### Task 7: Final — update CLAUDE.md and archive the plan

**Files:**
- Modify (maybe): `CLAUDE.md`
- Move: this plan file

- [ ] If `CLAUDE.md` documents the authorization model (it does mention OAuth/session/cluster auth — check), update it to describe the new provider-level `allowed_users` and remove any `super_users` references.
- [ ] Create `docs/plans/completed/` directory if not present: `mkdir -p docs/plans/completed`.
- [ ] Move this plan file: `mv docs/plans/20260512-provider-allowed-users.md docs/plans/completed/`.

## Risks & Behavior Changes

1. **Silent privilege revocation for legacy `super_users:` configs.** Per locked brainstorm decision: no deprecation warning, no log. Deployments still shipping a top-level `super_users:` block to a new plugin will see those users denied. The unknown YAML field is ignored by the parser. **Mitigation**: communicate the change in the release notes / changelog; the Post-Completion section below lists the operator migration path.
2. **Coordinated release required.** Plugin and xds must ship together. Mixed-version deployment (old plugin + new xds, or vice versa) is broken in subtle ways:
   - Old xds + new plugin: xds emits `super_users:` which the new plugin ignores → silent revocation.
   - New xds + old plugin: new xds no longer emits `super_users:` → silent revocation for any user who only had super_users-based access.
   - **Mitigation**: release gate in Task 6 — both built from the same commit, deployed atomically.
3. **Audit log volume change.** The "permission granted" audit log at filter.go:218-219 now also fires when only `provider.allowed_users` is configured. Deployments leaning heavily on provider-level allow will see log volume increase. **Mitigation**: documented in Overview; ops teams can budget log capacity if needed.
4. **Provider grant reaches unconfigured clusters.** A user in `provider.allowed_users` can access clusters that have no `Clusters[]` entry, because the provider check runs before the cluster lookup. This mirrors the reach of old `super_users` but scopes it to the provider. **Mitigation**: documented in Overview; `TestProviderAllowGrantsForClusterWithoutEntry` (Task 3) locks the behavior in tests so it can't silently regress.

## Post-Completion

*Items requiring manual intervention or external systems — no checkboxes, informational only.*

**Coordinated release:**
- Plugin (`.so`) and xds binaries must ship together. Sequence:
  1. Build both with the new code on the same commit.
  2. Deploy both atomically (same release tag).
  3. Avoid mixed-version deployments where xds still emits `super_users:` to a new plugin — access would silently change.

**Operator YAML migration (for deployments outside this repo):**
- Any production `gateway-auth*.yaml` or equivalent operator config with a top-level `super_users:` block must be rewritten before deployment:
  - Move each username under the relevant `providers.<name>.allowed_users:` list (whichever provider those users actually authenticate through).
  - If the deployment used a single provider, this is a near-mechanical move.
  - If multiple providers, decide per-user which provider's allowed_users they belong in.
- This repo's checked-in YAML files (`xds/gateway-auth.yaml`, `xds/gateway-auth-ssl.yaml`, `xds/envoy-xds.yaml`, `xds/base-envoy.yaml`) contain no `super_users:` blocks — no in-repo migration needed.

**Manual verification:**
- Spin up `example/standalone/` or `example/filter-chain/` with a provider configured to have `allowed_users: ["testuser"]` and a cluster with no `allowed_users`. Confirm `testuser` can reach the cluster.
- Repeat with provider `allowed_users: []` and cluster `allowed_users: ["testuser"]`. Confirm permission still works (fall-through).
- Repeat with neither list containing the user. Confirm denial. Check that the new debug log fires (with `LOG_LEVEL=DEBUG`).
