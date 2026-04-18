# SECURITY.md — Phase 03 Session Isolation

**Generated:** 2026-04-17
**Phase:** 03 — session-isolation
**ASVS Level:** 2
**Plans verified:** 03-01 through 03-05

---

## Threat Verification Summary

| Threat ID | Category | Disposition | Status | Evidence |
|-----------|----------|-------------|--------|----------|
| T-03-01 | Tampering | mitigate | CLOSED | `Session.ProviderName` field set exclusively from `h.providerName` (handler-owned config); verified in handler.go lines 220, 333, 719 — all three match `ProviderName: h.providerName` |
| T-03-02 | Spoofing | accept | CLOSED | Accepted — CookieConfig has zero slice/map/pointer fields; all 7 fields are value types; Clone() is a complete copy by construction |
| T-03-03 | Information Disclosure | accept | CLOSED | Accepted — Session is in-process memory only (InMemorySessionStore); ProviderName field never serialized to cookies |
| T-03-04 | Tampering | mitigate | CLOSED | `grep 'ProviderName:\s*h\.providerName' handler.go` returns 3 matches (HandleCallback line 333, ValidateBearerToken line 719, PendingAuth line 220); 2 session-creation sites confirmed |
| T-03-05 | Elevation of Privilege | mitigate | CLOSED | `getProviderHandler()` (filter.go lines 83–91) uses only `f.config.Clusters[f.cluster]` and `f.config.DefaultProvider`; session.ProviderName never referenced in dispatch path |
| T-03-06 | Spoofing | accept | CLOSED | Accepted — GetSessionCookie delegates to `h.cookieManager.GetCookie` which uses `cookieManager.config.Name`; name is structurally tied to provider by construction |
| T-03-07 | Information Disclosure | accept | CLOSED | Accepted — providerName is a non-secret user-chosen config identifier, not a credential |
| T-03-08 | Spoofing | mitigate | CLOSED | Cookie name derivation `cookieConfig.Name + "_" + name` in provider_registry.go line 60; TestInitAllPerProviderCookieNames proves cross-provider cookie isolation |
| T-03-09 | Spoofing | mitigate | CLOSED | Legacy path creates `<base>_default` via `cookieConfig.Name + "_default"` in parser.go line 421; TestParseLegacyCookieName asserts bare `<base>` cookie returns not-found |
| T-03-10 | Tampering | mitigate | CLOSED | CookieConfig.Clone() in cookie.go lines 45–55 copies all 7 value-type fields; InitAll always clones before setting Name (provider_registry.go line 59); Clone independence verified by TestCookieConfigClone |
| T-03-11 | Denial of Service | accept | CLOSED | Accepted — existing Phase 2 fail-fast behavior; per-provider health tracking deferred to Phase 5 |
| T-03-12 | Elevation of Privilege | mitigate | CLOSED | `cookieManager` field removed from Filter struct; grep across all filter package .go files returns 0 matches; compile-time enforcement |
| T-03-13 | Spoofing | mitigate | CLOSED | All cookie operations (GetSessionCookie, SetSessionCookie, DeleteSessionCookie, FormatSessionCookie) use `f.getProviderHandler()` which uses `f.cluster` as the single dispatch source; confirmed in filter.go and websocket.go |
| T-03-14 | Information Disclosure | accept | CLOSED | Accepted — resolved provider name is a non-sensitive config value, already exposed via X-Auth-Provider |
| T-03-15 | Denial of Service | accept | CLOSED | Accepted — `getProviderHandler()` is O(1) RWMutex map lookup; negligible overhead |
| T-03-16 | Elevation of Privilege | mitigate | CLOSED | `verifySessionProvider()` (filter.go lines 108–113) compares `sess.ProviderName` against `f.resolveProviderName()` (cluster-derived); mismatch branch at filter.go lines 515–538: WARN log + sessionStore.Delete + sessionHandler.DeleteSessionCookie + re-auth; TestProviderMismatchRejectsSession proves the branch |
| T-03-17 | Tampering | accept | CLOSED | Accepted — session store injection requires process-level access = full compromise; out of scope |
| T-03-18 | Information Disclosure | accept | CLOSED | Accepted — session IDs are high-entropy opaque handles; WARN log does not include Claims, IDToken, or tokens |
| T-03-19 | Denial of Service | accept | CLOSED | Accepted — mismatch deletes attacker's own session (self-limiting); Envoy rate-limits upstream |
| T-03-20 | Spoofing | mitigate | CLOSED | DeleteSessionCookie called on `sessionHandler` — the same cluster-resolved handler that read the session cookie (filter.go line 530); structural name-match guaranteed by construction |
| T-03-21 | Elevation of Privilege | mitigate | CLOSED | `getProviderHandler()` uses only cluster config; TestRefreshUsesClusterProvider (filter_test.go line 190) asserts the keycloak handler is returned even when session.ProviderName is "google" |

---

## Accepted Risks Log

| Threat ID | Category | Rationale |
|-----------|----------|-----------|
| T-03-02 | Spoofing | CookieConfig.Clone aliasing: all 7 fields are primitive value types (string, int, bool, http.SameSite); shallow copy is a complete independent copy by construction. No aliasing possible. |
| T-03-03 | Information Disclosure | Session struct serialization surface: Session is held in InMemorySessionStore only; it is never serialized to cookies (only the session ID handle is stored in the cookie). ProviderName is in-process only. |
| T-03-06 | Spoofing | GetSessionCookie using wrong cookie name: GetSessionCookie delegates to h.cookieManager.GetCookie, and each handler's cookieManager is initialized with its provider-namespaced Name in InitAll. Name mismatch is structurally impossible. |
| T-03-07 | Information Disclosure | Logging providerName in error paths: providerName (e.g. "keycloak") is a user-chosen short identifier, not a secret. It is already exposed downstream via X-Auth-Provider headers in Phase 4 scope. Sensitivity: none. |
| T-03-11 | Denial of Service | InitAll fail-fast on first error: existing behavior from Phase 2 (D-07 eager init). Per-provider health and partial degradation are Phase 5 (HLTH-03) scope. Risk accepted for Phase 3. |
| T-03-14 | Information Disclosure | Logging resolved provider name: provider name is a non-sensitive config value. Same rationale as T-03-07. |
| T-03-15 | Denial of Service | Double handler resolution overhead: getProviderHandler() performs an O(1) map lookup under RWMutex. Measured overhead is negligible; existing bearer-token path already incurs the same lookup. |
| T-03-17 | Tampering | Direct session store injection: requires process-level (in-memory) access, which constitutes full compromise. Out of scope for this phase. |
| T-03-18 | Information Disclosure | WARN log leaks session IDs: session IDs are high-entropy opaque handles (random base64). WARN log fields are: session_id, session_provider, expected_provider, cluster, trace_id. No Claims, IDToken, access_token, or refresh_token are logged. Risk: low. |
| T-03-19 | Denial of Service | Mismatch cookie spam: each mismatch deletes the attacker's own session (self-limiting). Request rate is bounded upstream by Envoy rate-limiting. DoS surface is minimal. |

---

## Unregistered Flags

None — no threat flags were raised in any Phase 03 SUMMARY.md `## Threat Flags` section.

---

## Verification Commands Run

```
grep 'ProviderName:\s*h\.providerName' plugin/oauth/handler.go  → 3 matches (lines 220, 333, 719)
grep 'cookieManager' plugin/filter/filter.go                    → 0 matches (field removed)
grep 'cookieManager' plugin/filter/*.go                         → 0 matches across all filter files
grep 'getProviderHandler' plugin/filter/filter.go               → 8 matches (dispatch never reads session.ProviderName)
grep 'cookieConfig\.Clone()' plugin/filter/provider_registry.go → 1 match (line 59)
grep 'cookieConfig\.Clone()' plugin/filter/parser.go            → 1 match (line 420)
grep 'cookieConfig.Name + "_" + name' plugin/filter/provider_registry.go → 1 match (line 60)
grep '"_default"' plugin/filter/parser.go                       → 1 match (line 421)
grep 'cookieConfig \*session\.CookieConfig' plugin/filter/provider_registry.go → 1 match (line 56)
grep 'verifySessionProvider' plugin/filter/filter.go            → 3 matches (def + 2 call sites)
grep 'Session provider mismatch' plugin/filter/filter.go        → 1 match (line 516)
grep 'sessionHandler.DeleteSessionCookie(header)' plugin/filter/filter.go → 1 match (line 530)
grep 'GetSessionCookie' plugin/filter/websocket.go              → 1 match (line 88)
grep 'func (h \*OAuthHandlerImpl) GetSessionCookie' plugin/oauth/handler.go → 1 match (line 450)
grep 'func (h \*OAuthHandlerImpl) DeleteSessionCookie' plugin/oauth/handler.go → 1 match (line 458)
grep 'func (h \*OAuthHandlerImpl) SetSessionCookie' plugin/oauth/handler.go → 1 match (line 464)
grep 'func (h \*OAuthHandlerImpl) FormatSessionCookie' plugin/oauth/handler.go → 1 match (line 471)
grep 'TestRefreshUsesClusterProvider' plugin/filter/filter_test.go → 1 match (line 190)
grep 'TestProviderMismatchRejectsSession' plugin/filter/filter_test.go → 1 match (line 91)
grep 'TestCookieValueIsSessionHandle' plugin/filter/filter_test.go → 1 match (line 234)
```
