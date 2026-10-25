# Remove client-controlled X-Skip-Auth bypass

## Overview
- Fixes Gitea issue #3: any client can send `X-Skip-Auth: <anything>` and reach every non-exempt service behind the gateway without logging in.
- Root cause: `plugin/filter/decode.go:55-63` returns `api.Continue` when the header named by `skip_auth_header_name` is present and non-empty. The header is never stripped from inbound requests (`stripUntrustedHeaders` in `plugin/filter/filter.go:312` only removes `RemoveHeaders`, and `ensureIdentityHeadersStripped` in `plugin/filter/parser.go:153` does not add the skip header). `xds/app/resources.go:145` hard-codes `skip_auth_header_name: "X-Skip-Auth"` for the whole gateway. A captured prod config dump (gitignored `tmp/config-dump:3107`) shows prod receives this key.
- Confirmed live on 2026-10-25: `curl -H 'X-Skip-Auth: 1' https://echo2.rashpile.net/` returns `503 no healthy upstream` (the request passed the filter and reached the router), while the same request without the header returns `401`.
- Fix: remove the skip-auth bypass from the filter. A config that still sets `skip_auth_header_name` is accepted, ignored, and logged at Warn (fail closed). The xDS server stops emitting the key. Trusted, operator-controlled bypass stays available through the existing `exclude: true` (cluster) and `exclude_paths` / `websocket_exclude_paths` settings.

## Context (from discovery)
- files/components involved:
  - `plugin/filter/decode.go`: the bypass branch (lines 55-63) and the comment block above `stripUntrustedHeaders` (lines 41-45)
  - `plugin/filter/parser.go`: the `OAuthConfig.SkipAuthHeaderName` field (line 70), its default (line 134), parsing in `populateConfig` (lines 268-270), and the clone in `Merge` (parser.go:531-565, field at line 562)
  - `plugin/filter/filter.go`: the `stripUntrustedHeaders` doc comment mentions skip-auth paths (lines 308-311)
  - `plugin/filter/filter_test.go`: the `recordingHandler` (line 22), `capturingHeaderMap` (line 269), `captureCallbacks` / `captureDecoderCallbacks` (lines 889-912), and `buildCallbackFilter` (line 917) helpers; `zaptest/observer` is already imported (line 13)
  - `plugin/filter/parser_test.go`: the `baseConfig()` + `buildAny()` + `(&Parser{}).parseRawConfig()` pattern (lines 17, 32, 343-360)
  - `plugin/filter/logger.go`: the package variable `logger` (line 14), returned by `GetLogger()` (line 77)
  - `xds/app/resources.go`: the `createHTTPConnectionManager` plugin config map (line 145)
  - `xds/app/resources_test.go`: the `extractPluginTypedStruct` helper (line 537) and the `TestProviderAllowedUsersOmittedWhenEmpty` pattern (line 614)
  - docs/examples: `README.md:149`, `plugin/filter/llms.txt:517`, `example/zipkin/envoy.yaml:63`, `example/filter-chain/envoy.yaml:78`
- related patterns found:
  - spoof protection is centralized: `stripUntrustedHeaders` runs before every early return in `DecodeHeaders` (T-04-01)
  - the parser reads `map[string]interface{}` keys and already ignores unknown keys, so dropping a key fails closed without breaking Envoy config loading
  - tests swap nothing global today; there is no `t.Parallel` in `plugin/filter`, so temporarily replacing the package `logger` var in a test is safe
- dependencies identified: none new
- no legitimate producer of `X-Skip-Auth` exists in the repo. No xDS route, template, or `request_headers_to_add` sets it. In `example/zipkin`, `header_to_metadata` with `remove: true` strips it before the Go filter. In `example/filter-chain`, the skip header (`X-User`) is the same as `user_username_header_name`, which `ensureIdentityHeadersStripped` already strips. Consumers outside the repo are checked before deploy (see Post-Completion).
- gitignored, so not edited: `xds/.plan/envoy.yaml`, `tmp/`, `docs/superpowers/`. `docs/plans/` is gitignored as well, so committing this plan needs `git add -f`.

## Development Approach
- **testing approach**: TDD (tests first). Write the regression test, watch it fail against current code, then fix.
- complete each task fully before moving to the next
- make small, focused changes
- **CRITICAL: every task MUST include new/updated tests** for code changes in that task
  - tests are not optional - they are a required part of the checklist
  - write unit tests for new functions/methods
  - write unit tests for modified functions/methods
  - add new test cases for new code paths
  - update existing test cases if behavior changes
  - tests cover both success and error scenarios
- **CRITICAL: all tests must pass before starting next task** - no exceptions
- **CRITICAL: update this plan file when scope changes during implementation**
- run tests after each change
- maintain backward compatibility: configs containing `skip_auth_header_name` must still parse

## Testing Strategy
- **unit tests**: required for every task (see Development Approach above)
  - filter: `go test ./plugin/filter/...` (plugin/ belongs to the root module)
  - xDS: `cd xds && go test ./...` (separate module, not covered by `make test`)
  - full: `make test` **and** `cd xds && go test ./...`
- **e2e tests**: the project has no UI e2e suite. Production verification is a manual curl (see Post-Completion)

## Progress Tracking
- mark completed items with `[x]` immediately when done
- add newly discovered tasks with ➕ prefix
- document issues/blockers with ⚠️ prefix
- update plan if implementation deviates from original scope
- keep plan in sync with actual work done

## Solution Overview
- **Remove, don't patch.** Auto-adding the skip header to `RemoveHeaders` would also close the hole. But stripping runs before the check, so the check would become dead code that still reads as a working feature. Deleting the branch and the field is smaller and honest.
- **Fail closed with a Warn.** `populateConfig` keeps recognizing `skip_auth_header_name`. When the key is non-empty, it logs a Warn saying the key is ignored and pointing to `exclude` / `exclude_paths`. It does not store the value. Envoy still loads old configs, and every request goes through auth.
- **No extra stripping of `X-Skip-Auth`.** Once the filter ignores the header, it carries no meaning. The pre-deploy check confirms nothing downstream reads it. Operators who want it gone can list it in `remove_headers`.
- **xDS stops emitting the key.** A new xDS server in front of an old filter `.so` therefore also closes the hole, because the old filter treats an absent key as an empty `SkipAuthHeaderName` (parser.go:134 default).

## Technical Details
- `OAuthConfig` loses the `SkipAuthHeaderName` field. Both places that set it are updated: the `parseRawConfig` defaults and the `Merge` clone.
- `populateConfig` replaces the assignment at `parser.go:268-270` with:
  ```go
  // skip_auth_header_name was removed: any client could send the header and
  // bypass auth (issue #3). Accept the key so old configs still load, but ignore it.
  if skipAuthHeaderName, ok := m["skip_auth_header_name"].(string); ok && skipAuthHeaderName != "" {
      GetLogger().Warn("skip_auth_header_name is no longer supported and is ignored; use cluster exclude or exclude_paths",
          zap.String("header", skipAuthHeaderName))
  }
  ```
- Parser tests capture the Warn by swapping the package logger:
  ```go
  core, logs := observer.New(zap.WarnLevel)
  orig := logger
  logger = zap.New(core)
  t.Cleanup(func() { logger = orig })
  ```
  They then filter `logs.All()` by a message containing `skip_auth_header_name`, rather than asserting a total count, so unrelated Warns added later don't break them.
- `DecodeHeaders` drops lines 55-63. The comment at lines 41-45 drops the "skip-auth paths" wording and the sentence starting "Skip-auth deployments must carry identity…".
- The xDS `pluginConfig` map drops `"skip_auth_header_name": "X-Skip-Auth"`.
- The `Version` in `plugin/filter/version.go` is bumped from 0.2.2 to 0.2.3, because operators can observe the change (a config key is now ignored).

## What Goes Where
- **Implementation Steps** (`[ ]` checkboxes): code changes, tests, and docs in this repo
- **Post-Completion** (no checkboxes): the pre-deploy consumer check, the image build and deploy to prod, live curl verification, and closing issue #3

## Implementation Steps

### Task 1: Regression test: a client-supplied X-Skip-Auth must not skip auth

**Files:**
- Modify: `plugin/filter/filter_test.go`

- [x] add a `cluster string` field to `captureCallbacks` and a `StreamInfo()` method that always returns `&stubStreamInfo{cluster: c.cluster}`. `stubStreamInfo` embeds `api.StreamInfo` (the same nil-embedded-interface pattern as `captureCallbacks`). Its `UpstreamClusterName()` returns `(cluster, cluster != "")`
- [x] write `TestDecodeHeadersIgnoresClientSkipAuthHeader`:
  - build the filter via `buildCallbackFilter`, register `h := &recordingHandler{}` (empty `cookieValue`, so there is no session) with `registry.Register("keycloak", h)`, and set `f.config.DefaultProvider = "keycloak"` and, for now, `f.config.SkipAuthHeaderName = "X-Skip-Auth"` (the field goes away in Task 2)
  - send `:path=/private`, `X-Skip-Auth: 1` via `capturingHeaderMap`. That map is case-sensitive, so spell the name exactly as in the config
  - assert `result == api.LocalReply`, `dec.statusCode == 401`, `dec.details == "auth_failure"`, and `h.getSessionCookieCalls == 1`, which shows the request went through real auth
- [x] write guard test `TestDecodeHeadersExcludedPathStillContinues` (it passes before and after the fix). Table cases: the path is in `ExcludePaths`, and `cbs.cluster = "c1"` with `Clusters["c1"] = ClusterConfig{Exclude: true}`. Both must return `api.Continue`, which shows trusted config-based bypass is unaffected
- [x] run `go test ./plugin/filter/ -run 'TestDecodeHeaders'`. `TestDecodeHeadersIgnoresClientSkipAuthHeader` must FAIL against current code (it gets `Continue`), proving the bypass. The guard test must pass

### Task 2: Remove the bypass from the filter

**Files:**
- Modify: `plugin/filter/decode.go`
- Modify: `plugin/filter/parser.go`
- Modify: `plugin/filter/filter.go`
- Modify: `plugin/filter/filter_test.go`

- [x] delete the `SkipAuthHeaderName` branch in `DecodeHeaders` (`decode.go:55-63`) and fix the comment at `decode.go:41-45`
- [x] remove the `SkipAuthHeaderName` field from `OAuthConfig` (`parser.go:70`), its default (`parser.go:134`), and the `Merge` clone (`parser.go:562`). The `populateConfig` assignment (`parser.go:268-270`) is deleted here too so the package compiles; Task 3 adds the Warn-only block in its place
- [x] update the `stripUntrustedHeaders` doc comment (`filter.go:308-311`) to drop the mention of skip-auth paths
- [x] drop the `SkipAuthHeaderName: "X-Skip-Auth"` line from the Task 1 test config (the field no longer exists). Keep the `X-Skip-Auth: 1` request header, so the test still proves the header has no effect
- [x] run `go test ./plugin/filter/...`. Everything must pass, including `TestDecodeHeadersIgnoresClientSkipAuthHeader`

### Task 3: Fail closed with a Warn on a legacy `skip_auth_header_name`

**Files:**
- Modify: `plugin/filter/parser.go`
- Modify: `plugin/filter/parser_test.go`

- [x] write `TestParseLegacySkipAuthHeaderNameIgnored`: `baseConfig()` + `cfg["skip_auth_header_name"] = "X-Skip-Auth"`, with the observer logger swap from Technical Details. Assert that `parseRawConfig` returns no error and that exactly one observed entry has a message containing `skip_auth_header_name`
- [x] write guard test `TestParseNoSkipAuthWarnWhenAbsentOrEmpty`, a table with the key absent and the key `""`. Assert that no observed entry mentions `skip_auth_header_name`. It passes against current code, which is expected
- [x] run the tests: confirm `TestParseLegacySkipAuthHeaderNameIgnored` FAILS (there is no Warn yet)
- [x] add the Warn-only block from Technical Details in `populateConfig` right after the `auth_provider_header_name` parsing, where Task 2 deleted the old assignment (`parser.go:268-270`)
- [x] run `go test ./plugin/filter/...`. Must pass before Task 4

### Task 4: Stop emitting `skip_auth_header_name` from xDS

**Files:**
- Modify: `xds/app/resources.go`
- Modify: `xds/app/resources_test.go`

- [x] write `TestPluginConfigOmitsSkipAuthHeaderName`: build a minimal `GatewayConfig`, call `createHTTPConnectionManager`, decode the result with `extractPluginTypedStruct`, and assert that the `skip_auth_header_name` key is absent (follow `TestProviderAllowedUsersOmittedWhenEmpty`)
- [x] run `cd xds && go test ./app/ -run TestPluginConfigOmitsSkipAuthHeaderName` and confirm it FAILS
- [x] remove `"skip_auth_header_name": "X-Skip-Auth"` from `pluginConfig` in `xds/app/resources.go:145`
- [x] run `cd xds && go test ./...`. Must pass before Task 5

### Task 5: Update docs, examples, and version

**Files:**
- Modify: `README.md`
- Modify: `plugin/filter/llms.txt`
- Modify: `example/zipkin/envoy.yaml`
- Modify: `example/filter-chain/envoy.yaml`
- Modify: `plugin/filter/version.go`

- [x] remove `skip_auth_header_name` from the README config example (`README.md:149`) and add a short note in the README config section: "`skip_auth_header_name` was removed in 0.2.3; the key is ignored with a warning. Use cluster `exclude` or `exclude_paths` for trusted bypass."
- [x] delete the `skip_auth_header_name` row from `plugin/filter/llms.txt:517`. Don't add a "removed" note there, since the file is served publicly at `/oauth/llms.txt` and describing a former bypass in it is noise
- [x] remove the `skip_auth_header_name` lines from `example/zipkin/envoy.yaml:63` and `example/filter-chain/envoy.yaml:78`. Leave the `header_to_metadata` filters in place; they are independent filter-chain examples
- [x] bump `Version` in `plugin/filter/version.go` to `0.2.3`
- [x] run `go test ./plugin/filter/...` (llms.txt is embedded and tested by `llms_test.go`). Must pass
- [x] run `git grep -n -i -e skip_auth_header_name -e SkipAuthHeaderName -- ':!docs/plans'`. Expected hits are the Warn block in `parser.go`, the tests in `parser_test.go`, and the README removal note (also the Task 4 absence test in `xds/app/resources_test.go`)

### Task 6: Verify acceptance criteria
- [x] verify a client-supplied `X-Skip-Auth` (or any former skip header) never yields `api.Continue` on a protected path (TestDecodeHeadersIgnoresClientSkipAuthHeader: 401 auth_failure; the bypass branch is gone from decode.go)
- [x] verify that legacy configs with `skip_auth_header_name` still parse and log a Warn (TestParseLegacySkipAuthHeaderNameIgnored)
- [x] verify that `exclude`, `exclude_paths`, and `websocket_exclude_paths` behave the same as before (existing tests green)
  - ➕ no test covered `websocket_exclude_paths`, so a websocket case was added to `TestDecodeHeadersExcludedPathStillContinues`
- [x] run the full test suite: `make test` and `cd xds && go test ./...`
- [x] run `go vet` on both modules (and `golangci-lint` if it is installed locally)
  - ⚠️ local golangci-lint v2.11.4 can't load go1.27.2 export data (it panics, and a rebuild fails typecheck on stdlib imports). Tool/toolchain mismatch, not a code issue; `go vet` and `gofmt -l` are clean
- [x] verify that test coverage for `plugin/filter` did not drop: `make test-coverage` (used plain `go test -cover`: main 33.7% -> branch 39.3%)

### Task 7: [Final] Update documentation
- [x] update README.md if needed (beyond Task 5) (no further changes needed)
- [x] move this plan to `docs/plans/completed/` (deferred to orchestrator, runs after reviews)

## Post-Completion
*Items requiring manual intervention or external systems - no checkboxes, informational only*

**Before deploy** (a legitimate internal caller that relied on the bypass would otherwise break silently):
- grep docker-env/envoy (gateway-auth.yaml, any Envoy templates) and the upstream apps (at least ai-learn-app) for `X-Skip-Auth` / `x-skip-auth` / `skip_auth_header_name`. Remove config references. If some caller legitimately depends on the bypass, move it to cluster `exclude` / `exclude_paths` first

**Deploy**:
- Gitea Actions builds the images. Deploy both the filter `.so` and the xDS server to the `envoy` container on dragonstone (docker-env/envoy compose). Either one alone already closes the hole, but deploy both

**Manual verification**:
- run `curl -s -o /dev/null -w '%{http_code}\n' -H 'X-Skip-Auth: 1' https://echo2.rashpile.net/` and expect `401` (the same as without the header), not `503 no healthy upstream` or `200`
- spot-check one ai-learn-app content pack URL with `X-Skip-Auth: 1`; it must not be served as `default-user`
- after deploy, prod Envoy logs must not show the new Warn. Its absence confirms the xDS server no longer sends the key

**Forensics (optional)**:
- the filter's own logs can't show past abuse. `LogAccess` (logger.go:82) records no request headers, and the "Skipping authentication" line (decode.go:57) is Debug, which is off at the default INFO. Use Envoy's own access log, and only if its format includes `%REQ(X-SKIP-AUTH)%`. Otherwise, look for unauthenticated 2xx/5xx on protected hosts from client IPs with no prior `/oauth/callback`

**Tracking**:
- close issue #3 with the fix commit, and leave a note on ai-learn-app #188
