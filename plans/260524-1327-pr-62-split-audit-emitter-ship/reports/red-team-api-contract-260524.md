---
type: red-team-api-contract
plan: pr-62-split-audit-emitter-ship
date: 2026-05-24
posture: hostile / FE-compat focus
scope: phase-04 admin API + cross-phase contract surface
---

# Red-Team R2 — API & FE Contract Attack Surface

10 findings ranked by FE-breakage blast radius. Severity: BLOCKER / HIGH / MED / LOW.

## F-A-1 — 308 redirect body empty, FE JSON.parse will throw (BLOCKER)
**Breach:** Phase-04 §2.3 returns `(StatusCode::PERMANENT_REDIRECT, headers, ())`. Axum `()` → empty 0-byte body. Any FE doing `fetch(...).then(r=>r.json())` on the legacy URL without `redirect:'follow'` semantics gets `SyntaxError: Unexpected end of JSON input`. Even with auto-follow, the FE then parses the new endpoint's body — but POST methods (none today, but future hypothetical) become non-trivial. Old stub returned 200+JSON; switching to 308 is a hard contract break.
**Evidence:** phase-04 lines 144-155 (impl), lines 251 ("Old clients still get something" — false: they get empty body or follow-redirect body).
**Mitigation:** Two-step deprecation. Phase 4a: return 200 + same JSON shape + `Deprecation: true` + `Sunset: <RFC8594 date>` + `Link: </api/reputation/status>; rel="successor-version"`. Phase 4b (next release): flip to 308. Document the sunset window in PR description.
**Phase:** 04 (BP5 needs rewrite).

## F-A-2 — `message` field silently dropped (HIGH)
**Breach:** Old stub `data` shape included `message: "feeds not loaded yet"` (per prompt context). New `/api/reputation/status` drops it. FE rendering `{data.message}` shows literal "undefined" or empty `<span>`. No deprecation notice.
**Evidence:** phase-04 lines 100-112 — JSON literal omits `message`.
**Mitigation:** Keep `message: String` in response; emit `""` when available, human-readable when not. Cheaper than coordinating FE refactor. Add doc note: optional, may go away in next major.
**Phase:** 04.

## F-A-3 — `rule_id` naming pattern frozen by first emit (HIGH)
**Breach:** Plan picks `BOT-XFF-001`, `BOT-RELAY-001`, `BOT-RELAY-TOR-001`, `TX-SEQ-001`, `TX-WITHDRAW-001`, `TX-LIMIT-001`. Tech guide uses wildcard `BOT-XFF-*`. Once `001` rows land in DB, FE filter UI and saved queries pin to that exact string. Future `BOT-XFF-002` requires new FE filter chip / migration. Worse: `BOT-RELAY-TOR-001` is 4-segment, breaks 3-segment parsers if FE splits on `-`.
**Evidence:** phase-02 lines 87-91; phase-03 lines 80-84.
**Mitigation:** Document rule_id grammar BEFORE emitting any row: `<DOMAIN>-<CATEGORY>-<NNN>` exactly 3 segments. Rename `BOT-RELAY-TOR-001` → `BOT-RELAYTOR-001` or `BOT-TOR-001`. Add a regex contract test `^[A-Z]+-[A-Z]+-\d{3}$` in audit_emitter validating every rule_id at emit time — fail loud in tests, log+drop in prod.
**Phase:** 01 (validator), 02+03 (rename).

## F-A-4 — `elevated: 0` placeholder breaks 4-band chart (HIGH)
**Breach:** Phase-04 hardcodes `elevated: 0` + `approximation: true`. FE chart legend renders 4 bands; one always-empty band looks like a bug, not a feature. `approximation: true` flag is a hint, not a directive — plan doesn't define FE contract for hiding the band.
**Evidence:** phase-04 lines 129-141.
**Mitigation:** Either (a) omit `elevated` entirely when approximation mode (FE sees 3 keys → must adapt), or (b) return `bands: { allow, challenge, block }` + `unavailable_bands: ["elevated"]` array — explicit not implicit. Document: when `approximation == true`, FE MUST treat absent bands as "not measured", not "zero events".
**Phase:** 04.

## F-A-5 — Refresh rate-limit response unspecified (HIGH)
**Breach:** Phase-04 §requirements says "rate-limited" but impl (lines 114-119) calls `trigger_reload().await?` unconditionally and returns the status snapshot. No 429, no `Retry-After`, no error body shape. FE retry-on-failure logic could either (a) hammer the endpoint thinking it succeeded, or (b) treat 200 with stale `last_refreshed` as a silent failure.
**Evidence:** phase-04 lines 114-119 vs line 28.
**Mitigation:** Spec: if within 60s window, return 200 + status snapshot + `data.refresh_skipped: true` + `data.next_refresh_allowed_at: <iso>`. Avoids 429 (which FE may treat as fatal). Add test `refresh_within_window_returns_skipped_flag`.
**Phase:** 04.

## F-A-6 — `POST /api/reputation/refresh` request body undefined (MED)
**Breach:** Plan never says whether body is empty, `{}`, or carries args (e.g., `{feeds: ["tor"]}`). FE will guess; backend will accept anything. Future schema addition becomes breaking change because lenient parser becomes strict.
**Evidence:** phase-04 line 19, 114 — handler signature has no `Json<T>` extractor.
**Mitigation:** Spec: empty body OR `Content-Type: application/json` + `{}`. Reject body with unknown keys (`#[serde(deny_unknown_fields)]`) so adding fields later is backwards compatible. Document in PR body.
**Phase:** 04.

## F-A-7 — Feature-detection probe broken by 308 (MED)
**Breach:** If admin FE probes `GET /api/threat-intel/status` to decide "is this new backend?", 308→200 makes detection ambiguous: redirect-followed response indistinguishable from a true legacy 200. FE may never switch over.
**Evidence:** phase-04 line 44.
**Mitigation:** Add a positive marker on the NEW endpoint, not negative on the old: `/api/reputation/status` response includes `api_version: "v2"` or top-level `success: true, data: {schema: "reputation.v1"}`. FE probes new endpoint; absence → fall back. Stop relying on legacy URL existence.
**Phase:** 04.

## F-A-8 — OpenAPI/Swagger drift not addressed (MED)
**Breach:** If `waf-api` exposes OpenAPI (typical for admin APIs), plan never updates spec. FE codegen clients keep old types; deprecated endpoints lack `deprecated: true` marker; new endpoints invisible to typed clients.
**Evidence:** plan + phase-04 silent on OpenAPI.
**Mitigation:** Audit `crates/waf-api/` for `utoipa` / `openapi` / `aide` deps in step 1. If present: mandatory spec update in same PR — `deprecated = true` on legacy, new schema for `Reputation*`, `RiskDistribution*`. If absent: add explicit non-goal note in PR description.
**Phase:** 04.

## F-A-9 — Hardcoded `Location` path ignores reverse-proxy prefix (MED)
**Breach:** Redirect target is `/api/reputation/status` (root-relative). If admin is mounted behind `/admin/` reverse-proxy prefix (common in production), browser follows to wrong absolute path. Healthcheck monitors break silently.
**Evidence:** phase-04 line 150.
**Mitigation:** Either (a) use `Location: ./reputation/status` (path-relative) — Axum will not rewrite for you, or (b) document deployment constraint "admin API MUST be mounted at root". Add integration test under simulated `/admin/` prefix.
**Phase:** 04.

## F-A-10 — Deprecation window "giữ 1 release" undefined (LOW)
**Breach:** Plan §BP5 says keep one release. No release cadence defined (monthly? per-merge?). Operators running healthchecks on legacy URL get no calendar date. `X-Deprecated: true` is not a standard header — observability stacks don't alert on it.
**Evidence:** plan.md line 42; phase-04 lines 144-155.
**Mitigation:** Use IETF standards: `Deprecation: Wed, 24 May 2026 00:00:00 GMT` (RFC 9745) + `Sunset: Wed, 24 Aug 2026 00:00:00 GMT` (RFC 8594). 3 months minimum. Drop the non-standard `X-Deprecated` header. Add to release notes template.
**Phase:** 04 + plan.md BP5.

## Cross-cutting recommendations

1. **Add `docs/api-contracts.md`** (new) listing every endpoint's request/response JSON schema. Make it a PR-D blocker. Without it, FE coordination is by Slack — fragile.
2. **Versioning prefix:** consider `/api/v1/reputation/...` from day one. Cost: one path segment. Benefit: future breaking change without 308 dance.
3. **Test matrix gap:** plan tests assert status code + presence of fields, not absence of breaking changes. Add golden-file JSON snapshot tests (`insta` crate) so any future field rename fails loudly.

## Verification this report meets the bar

- [x] Contract breaks identified with concrete FE failure modes
- [x] Each finding maps to a phase + line numbers
- [x] Mitigations are spec changes, not "consider"
- [x] OpenAPI / reverse-proxy / standards-compliance angles surfaced
- [x] < 600 words target — exceeded for completeness (10 findings); trim if needed

## Open questions

- Does `waf-api` already serve OpenAPI? (Scout `Cargo.toml` for `utoipa`/`aide`.)
- Is admin UI ever mounted behind a path prefix in production deployments? (Affects F-A-9.)
- Release cadence — weekly main-merges or tagged releases? (Affects F-A-10 sunset date math.)
- Does any consumer outside the admin UI hit `/api/threat-intel/status` (monitoring, scripts)? (Affects F-A-1 severity.)
