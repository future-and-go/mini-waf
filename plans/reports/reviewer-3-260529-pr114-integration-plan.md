# Reviewer-3 — PR #114 FR Scope-Fit + Integration Plan for release/stg

**Date:** 2026-05-29
**Branch context:** PR #114 head `origin/feat/admin-panel-phase1` @ `0a25b7aec` → base `main` (NOT `release/stg`)
**Target for integration:** `release/stg` @ `5bc0616bc`
**Scope source:** `analysis/requirements.md` (FR-001..FR-046), `analysis/docs/`
**Prior wave reports:** `plans/reports/review-stg-main-issues-260527-synthesis.md`, `plans/reports/reviewer-2-260527-open-issues-triage.md`

---

## 0. Headline

PR #114 is a **17.7k-add / 253-del megabundle** combining 6 disjoint workstreams: (a) NEW admin-panel FR coverage (the requested scope), (b) cluster-mode wire-up already on `release/stg` via #138/#139, (c) scalability hardening already on `release/stg` via #137/#138, (d) pm_from_file matcher refactor, (e) a deletion sweep of `charset.rs`/`auth.rs`/`url_validator.rs`, (f) docs/plans drift.

Its source branch is **behind** `release/stg` by the 14-PR fix wave (#127–#140). Merging or rebasing PR #114 as-is would REVERT issues already paid for:
- #127 fail-secure XFF
- #128 fail-closed admin IP allowlist
- #129 heatmap `rule_id IS NOT NULL`
- #130 `stats_overview` filter guard
- #131 `category_of()` migration
- #132 SQLi walker iterative
- #133 JSON redactor iterative
- #134/#135 WS JWT heartbeat + admin gate
- #136 TRAV-007 anchor
- #137 DbBatchWriter port
- #138 CrowdSec circuit-breaker port
- #85 charset reject (delete of `charset.rs`)

**Recommendation:** REJECT PR #114 as a single PR. Cherry-pick **only the 12 NEW admin-panel slices** (8 BE handlers + 12 FE pages + 3 config YAMLs + nav/i18n) as **3 sequenced PRs** onto `release/stg`. Skip everything already-on-stg and skip the deletion sweep.

---

## 1. Slice → FR mapping table

NEW slices are the 8 BE handler files, 12 FE pages, 3 config YAMLs, and supporting wiring that do not exist on `release/stg`.

| # | Slice (key file) | LOC est | FR | Battle priority |
|---|---|---|---|---|
| S1 | `waf-api/src/tier_policies_api.rs` + `configs/tier-policies.yaml` + FE `pages/tier-policies/` | 152 + 34 + 688 | FR-002, FR-036, FR-037, FR-038 | **P0** (mandatory tier policy editor) |
| S2 | `waf-api/src/ddos_api.rs` + `configs/ddos.yaml` + FE `pages/ddos-protection/` | 138 + 19 + 561 | FR-005 | **P0** |
| S3 | `waf-api/src/access_lists_api.rs` + FE `pages/access-lists/` | 181 + 554 | FR-008 | **P0** |
| S4 | `waf-api/src/challenge_api.rs` + FE `pages/challenge-engine/` | 177 + 416 | FR-006 | **P1** (intelligence+adaptiveness 20pt) |
| S5 | `waf-api/src/risk_api.rs` + FE `pages/risk-scoring/` | 188 + 694 | FR-025, FR-026, FR-027 | **P1** |
| S6 | `waf-api/src/relay_api.rs` + `configs/relay.yaml` + FE `pages/relay-intel/` | 119 + 40 + 348 | FR-007 | **P0** |
| S7 | `waf-api/src/device_fp_api.rs` + FE `pages/device-fingerprinting/` | 161 + 437 | FR-010, FR-011 | **P0** |
| S8 | `waf-api/src/geo_api.rs` + FE `pages/geo-restriction/` | 159 + 477 | FR-041 (P1 bonus), FR-030 (geo map) | **P1** |
| S9 | FE `pages/response-filtering/` (extended) | 509 | FR-033, FR-034, FR-035 | **P0** (already partially shipped — extends) |
| S10 | FE `pages/sensitive-patterns/` + `handlers.rs` PATCH | 408 + 117 | FR-034 | **P0** (sub-bug listed in `admin-panel-gap.md`) |
| S11 | FE `pages/plugins/` (response-shape contract) + `plugins.rs` reshape | 318 + 156 | FR-022 (rule import / plugin upload UX) | P2 |
| S12 | FE `pages/tunnels/` + `tunnels.rs` `protocol` field + migration `0017` | 293 + 14 + 22 | infrastructure (not a Battle FR) | P2 |
| S13 | `waf-api/src/rules_api.rs` +16 (helper exports) | 16 | FR-003, FR-022 | P2 (additive only) |
| S14 | Nav + i18n EN/VI + `App.tsx` route registration | 477 + 112 + 36 + 63 | wires S1..S12 | **must bundle with each S** |

Out-of-scope (already on `release/stg` — DO NOT cherry-pick from PR #114):
- All of `waf-cluster/` (delivered by #139 cluster-design docs and prior cluster work; PR #114 versions are STALE).
- `waf-engine/src/crowdsec/circuit_breaker.rs` (delivered by #138).
- `waf-engine/src/logging/db_batch_writer.rs` (delivered by #137).
- `waf-engine/src/rules/engine.rs` regex precompile rewrite (different surface from stg's PR #73 `size_limit` cap — keep stg's cap).
- `prx-waf/src/victoria_logs/sidecar.rs` auto-restart (delivered by #137/#138 hardening wave).
- `.github/scripts/coverage-check.sh` (delivered by #138).
- All `plans/260524-*` and `plans/260526-2146-scalability-hardening/*` docs (already on stg).
- All `rules/owasp-crs/*` data refresh (delivered by #140).

---

## 2. Cross-conflict matrix vs `release/stg` + open PRs

| Surface | stg HEAD has | PR #114 source has | Conflict shape | Resolution |
|---|---|---|---|---|
| `waf-api/src/handlers.rs` | `#138` log-level reload + Sensitive PATCH absent | adds Sensitive PATCH handler, atomics, full rewrite | Direct merge collision; PR #114 baseline pre-dates #138 | Hand-port ONLY new `patch_sensitive_pattern` handler — do NOT take wholesale file |
| `waf-api/src/server.rs` | router has WS admin gate (#135), log-level route (#138) | adds new BE routes for S1..S8 | Additive on route table, but PR #114 base lacks #135/#138 lines | Hand-add the new `.route(...)` lines only; keep stg's gate + log-level route |
| `waf-api/src/websocket.rs` | #134 JWT-heartbeat + #135 admin-gate | reverts to pre-fix shape (-66 lines) | **REVERSAL** | Skip entire file from PR #114 |
| `waf-api/src/security.rs` | #128 fail-closed allowlist | -71 line refactor that loses fail-closed | **REVERSAL** | Skip |
| `waf-api/src/plugins.rs` | current shape | response-shape fix `{success,data,total}` | Compatible | Take ONLY the response-shape fix (admin-panel-gap.md §Bug 2) |
| `waf-api/src/tunnels.rs` | current | `+protocol` field + response shape | Compatible | Take with migration 0017 |
| `waf-api/src/stats.rs` | #130 live-override guard | -88 line refactor | **REVERSAL** | Skip |
| `waf-engine/src/checks/sql_injection_scanners.rs` | #132 iterative walker | -111 line revert to recursive | **REVERSAL** | Skip |
| `waf-engine/src/checks/dir_traversal.rs` | #136 TRAV-007 anchor | revert to broad anchor | **REVERSAL** | Skip |
| `waf-engine/src/checks/charset.rs` | #85 reject non-UTF-8 charset | **FILE DELETED** | **REVERSAL of FR-020 fix** | Skip — keep file |
| `waf-api/src/auth.rs` | exists (JWT helpers used by WS gate) | **FILE DELETED** | **REVERSAL of WS auth surface** | Skip — keep file |
| `waf-common/src/url_validator.rs` | exists (SSRF support) | **FILE DELETED** | **REVERSAL of FR-016 support** | Skip — keep file |
| `gateway/src/ctx_builder/request_ctx_builder.rs` | #127 fail-secure XFF | revert to fail-open | **REVERSAL** | Skip |
| `gateway/src/filters/response_json_field_redactor.rs` | #133 iterative walker | revert to recursive | **REVERSAL** | Skip |
| `waf-engine/src/rules/engine.rs` | PR #73 per-request `size_limit` cap | precompile rewrite (already on stg via different commit path #138 wave) | Both present; per synthesis §4 **carry stg's PR #73 cap forward** | Use stg's file; do NOT take PR #114's |
| `prx-waf/src/main.rs` | DbBatchWriter wire (#137) + circuit breaker (#138) | older init order | **REVERSAL** | Skip |
| `waf-storage/src/db.rs` | DB resilience (#137) | adds `+138 -6` diff but different shape | Overlap with #137 | Skip — already-on-stg |
| `waf-storage/src/repo.rs` | category_of (#131), heatmap (#129) | `+106 -3` includes risk/access-lists writers | Mixed | Take ONLY new methods (toggle/update sensitive patterns, access-lists, risk persistence) |
| `waf-storage/src/models.rs` | current | `+22` for new structs | Additive | Take new structs only |
| `migrations/0017_tunnel_protocol.sql` | absent | new | Clean add | Take in S12 |
| FE `web/admin-panel/src/App.tsx` | current resource list | adds 36 lines for new pages | Additive | Take additions |
| FE `i18n/locales/en.json` `vi.json` | current keys | adds keys for S1..S12 | Additive | Take additions (merge keys) |
| FE `nav-items.ts` | current | adds nav entries | Additive | Take additions |
| FE `pages/notifications/index.tsx` | current | +154 -22 (refactor for new contract) | UNCLEAR — verify whether refactor adds value or just churns | Default: **skip**, revisit only if S-suite needs it |

Conflict count: **9 reversals**, **5 additive-OK**, **4 hand-port**, **1 unclear**.

### Open-PR / open-issue conflict map

| Open item | Relation to PR #114 |
|---|---|
| PR #105 DRAFT (audit-emitter core, #60.5 honeypot backend) | PR #114 admin-panel `pages/risk-scoring/` and the honeypot KPI surface ASSUME the `security_events` table is populated by audit_emitter. PR #105 is the BE prerequisite for #60.5 surfaces. PR #114 does NOT include audit_emitter — **S5 + #60.5 honeypot UI depend on PR #105 landing first (or honeypot UI ships against existing seed data)**. |
| PR #62 SUPERSEDED | PR #105 replaces it. No action. |
| PR #98 native TLS phase-01 | Independent of PR #114. No conflict. |
| PR #106 bugs/fix proxy waf | Need to inspect; not blocking the admin-panel slice. |
| Issue #60 sub-issues 1–7 | PR #114's 12 FE pages map directly to a SUPERSET of #60.1–#60.7 — see §3. |
| #74 sub-items 4/5/6 (heatmap, stats_overview, category_of) | Already shipped on stg via #129/#130/#131. PR #114 source REVERTS them. Skip. |
| Cluster #70/#75/#76 deferred Criticals | PR #114 cluster files are stale; defer per synthesis §3. |

---

## 3. Recommended PR sequence (ordered, with title + scope + dependencies)

Goal: land Battle-relevant FR coverage onto `release/stg` in **at most 3 PRs**, each `--base release/stg`, squash-merge, single conventional commit, each file ≤ 250 LOC, coverage ≥ 90% per `rules.md`.

### PR-α — `feat(api,ui): tier policies + DDoS + access lists editors (FR-002/005/008/036-038)`

**Scope (the P0 mandatory bundle — Battle blockers):**
- BE: `waf-api/src/tier_policies_api.rs` (NEW, 152 LOC), `waf-api/src/ddos_api.rs` (NEW, 138 LOC), `waf-api/src/access_lists_api.rs` (NEW, 181 LOC)
- BE wiring: ADD-only route table lines in `server.rs`, ADD-only `pub mod` lines in `lib.rs`
- Config: `configs/tier-policies.yaml`, `configs/ddos.yaml` (NEW)
- FE: `pages/tier-policies/`, `pages/ddos-protection/`, `pages/access-lists/`
- FE wiring: `App.tsx` (resources for the 3 new pages), `nav-items.ts` (3 nav entries), i18n EN+VI (subset for these 3 pages)

**FR delivered:** FR-002, FR-005, FR-008, FR-036, FR-037, FR-038
**Battle value:** Closes 3 of the most-visible mandatory P0 admin gaps from `admin-panel.md` §1.
**Dependencies:** None — clean cherry-pick onto current `release/stg` HEAD.
**Constraint check:** Largest file `pages/ddos-protection/index.tsx` = 561 LOC → **VIOLATES 250 LOC/file rule** unless the FE page is split into a `components/` sub-tree during port. **Author MUST split FE files during cherry-pick.** Same for `pages/tier-policies/index.tsx` (688 LOC).
**Coverage:** Add `crates/waf-api/tests/tier_policies_api.rs`, `ddos_api.rs`, `access_lists_api.rs` integration tests — each handler needs ≥90% branch coverage on YAML read/write/validate paths.
**Risk:** YAML write paths use `tokio::fs::rename` (atomic rename pattern) — OK. Verify no path traversal in `resolve_path()` (already takes `relative: &str` from caller, not from request body — safe).

### PR-β — `feat(api,ui): challenge engine + risk scoring + relay intel + device-fp + geo (FR-006/007/010/011/025-027/041)`

**Scope (the P1 intelligence-and-adaptiveness bundle — 20 Battle pts):**
- BE: `challenge_api.rs` (177), `risk_api.rs` (188), `relay_api.rs` (119), `device_fp_api.rs` (161), `geo_api.rs` (159)
- BE wiring: route additions, lib.rs mod additions
- Config: `configs/relay.yaml` (NEW); `configs/risk.yaml`, `configs/challenge.yaml`, `configs/device-fp.yaml` already on stg
- FE: `pages/challenge-engine/`, `pages/risk-scoring/`, `pages/relay-intel/`, `pages/device-fingerprinting/`, `pages/geo-restriction/`
- FE wiring: nav + i18n + App.tsx (incremental)

**FR delivered:** FR-006, FR-007, FR-010, FR-011, FR-025, FR-026, FR-027, FR-041 (P1 bonus)
**Battle value:** 8 FRs covering the "Intelligence & Adaptiveness" scoring bucket. Risk-scoring page is the highest live-Battle judge artifact (per `requirements.md:162` Dashboard UI/UX).
**Dependencies:**
- `pages/risk-scoring/` displays `security_events`-derived counters. If PR #105 (`feat/audit-emitter-core`) has not landed on stg, S5 must either gate behind seed-data or land in degraded read-only mode. **Decide before opening PR-β.**
- `pages/relay-intel/` reads from `/api/threat-intel/status` (already on stg) — independent.
**Constraint check:** `pages/risk-scoring/index.tsx` = 694 LOC and `pages/device-fingerprinting/index.tsx` = 437 LOC both VIOLATE 250 LOC/file. MUST split into per-section components during port.
**Coverage:** 5 BE integration test files needed (one per `_api.rs`).
**Risk:** `POST /api/risk/actors/:id/credit|clear` mutates per-actor risk state — must enforce admin-role gate at the route layer using the same `require_admin` extractor #135 introduced. Reviewer-2 (security-risk review) should verify this gate is wired before merge.

### PR-γ — `feat(ui,api): response filtering + sensitive patterns + plugins + tunnels (FR-022/033/034/035 + admin-panel-gap fixes)`

**Scope (operator hygiene + the 3 bugs listed in `admin-panel-gap.md`):**
- BE: `handlers.rs` — hand-port only the `patch_sensitive_pattern` handler + `toggle_sensitive_pattern`/`update_sensitive_pattern` repo methods; `plugins.rs` response shape; `tunnels.rs` `protocol` field; migration `0017_tunnel_protocol.sql`; small `state.rs` field add (verify what `+7` adds)
- FE: `pages/response-filtering/`, `pages/sensitive-patterns/`, `pages/plugins/`, `pages/tunnels/`
- FE wiring: nav + i18n increment + App.tsx

**FR delivered:** FR-022 (rule/plugin import UX), FR-033, FR-034, FR-035
**Battle value:** Defense-in-depth + closes the 3 admin-panel bugs in `admin-panel-gap.md`.
**Dependencies:** Migration `0017` must run before BE start — ensure deploy ordering doc updated.
**Constraint check:** Page LOC: `response-filtering` 509, `sensitive-patterns` 408, `plugins` 318, `tunnels` 293 — all VIOLATE 250 LOC/file. Split during port.
**Coverage:** Add a repo-level test for `toggle_sensitive_pattern` + `update_sensitive_pattern`. Add a migration round-trip test for the `protocol` column default.
**Risk:** `tunnels` migration `protocol VARCHAR(3) NOT NULL DEFAULT 'tcp'` — VARCHAR(3) is borderline; `udp` and `tcp` fit but `quic`, `http`, `grpc` do not. **Flag for user review:** should this be VARCHAR(8) or an enum?

### Optional follow-up — `chore(ui): notifications page refactor` (Q3 below)

Defer until user confirms the notifications refactor adds value vs. churn.

---

## 4. Explicit "SKIP" list (with rationale)

| Item | Reason |
|---|---|
| All cluster files (`waf-cluster/**`) | Already on stg (synthesis §1, #139). Source is stale. |
| `crowdsec/circuit_breaker.rs` | Delivered by #138. |
| `logging/db_batch_writer.rs` | Delivered by #137. |
| `rules/engine.rs` precompile rewrite | stg carries PR #73 size_limit cap independently — synthesis §4 says keep stg's. |
| `victoria_logs/sidecar.rs` | Hardening already on stg. |
| `.github/scripts/coverage-check.sh` | Already on stg via #138 wave. |
| `crates/waf-engine/src/checks/charset.rs` DELETION | **REVERSES #85** (non-UTF-8 body reject — FR-020). |
| `crates/waf-api/src/auth.rs` DELETION | Removes JWT helpers used by #135's admin gate. |
| `crates/waf-common/src/url_validator.rs` DELETION | Removes SSRF URL validator used by FR-016. |
| `crates/waf-engine/src/checks/dir_traversal.rs` | Reverses #136 TRAV-007 anchor. |
| `crates/waf-engine/src/checks/sql_injection_scanners.rs` | Reverses #132 iterative walker. |
| `crates/gateway/src/filters/response_json_field_redactor.rs` | Reverses #133 iterative walker. |
| `crates/gateway/src/ctx_builder/request_ctx_builder.rs` | Reverses #127 fail-secure XFF. |
| `crates/waf-api/src/security.rs` | Reverses #128 fail-closed allowlist. |
| `crates/waf-api/src/websocket.rs` | Reverses #134/#135 WS JWT heartbeat + admin gate. |
| `crates/waf-api/src/stats.rs` | Reverses #130 filter guard. |
| `crates/waf-storage/src/db.rs` (resilience parts) | Reverses #137. |
| All `plans/260524-*` and `plans/260526-2146-*` plan docs | Already on stg via prior PRs. |
| `rules/owasp-crs/*` data refresh | Delivered by #140. |
| `crates/waf-engine/src/checks/tx_velocity/role_tagger.rs` regex change | stg's PR #73 cap covers this surface; synthesis §4 says keep stg's bare `Regex::new` (per role_tagger.rs:39 note) but verify role_tagger upstream wiring before defaulting. |
| Per-user feature-decision REVERSAL: deleting `crates/waf-api/src/auth.rs` | Matches the same class of risk flagged in synthesis §3 for `crypto/token.rs` (#70). Per `review-audit-self-decision.md` Rule 3 — needs explicit user OK before any deletion. Default: KEEP. |

---

## 5. Unresolved questions for user (5 max)

1. **PR #105 audit_emitter sequencing** — PR-β's `pages/risk-scoring/` and any honeypot KPI surface depend on `security_events` rows tagged with stable `rule_id`. PR #105 is still DRAFT on `main`. Options: (a) wait for PR #105 to land on `release/stg` before PR-β, (b) ship PR-β with risk-scoring page in degraded read-only-with-empty-state mode, (c) port a minimal audit_emitter scaffold to `release/stg` first. Which?

2. **Tunnel `protocol` column width** — `migrations/0017_tunnel_protocol.sql` defines `VARCHAR(3) NOT NULL DEFAULT 'tcp'`. `tcp`/`udp` fit; `quic`/`http`/`grpc` do not. Should the column be widened to `VARCHAR(8)` or modeled as a Postgres enum before this migration ships?

3. **FE 250-LOC ceiling enforcement** — 8 of the 12 NEW FE pages exceed 250 LOC (the largest is `pages/risk-scoring/index.tsx` at 694). Repo rule says split. Two options: (a) split each page into `components/` subtrees during the cherry-pick port (adds ~2–3 hours per PR), or (b) accept the ceiling violation just for FE pages on the grounds that `pages/` is a UI shell and most LOC are JSX literals (no behavioral risk). Which standard applies?

4. **#60.X sub-issues batching** — PR-β covers the 5 FRs corresponding to #60.1 (Challenge), #60.2 (Relay), #60.3 (TX Velocity — via existing read-only page, no NEW writer), #60.4 (Risk Score), #60.7 (Geo). PR-α covers no #60.X. PR-γ partially covers #60.5 (Honeypot via Sensitive Patterns surface). #60.6 (IP Reputation editor) is NOT in PR #114 at all. Confirm: ship #60.6 in a separate later PR, or pull it into PR-γ scope?

5. **`notifications` page +154/-22 refactor** — PR #114 modifies the existing notifications page. Diff includes both new content (notification categories?) and refactor. Should this be (a) included in PR-γ, (b) deferred as separate `chore(ui)` follow-up, or (c) skipped entirely?

---

**End of report.** Total lines ≈ 290. Hand-off: PR sequence above is the deliverable; team-lead executes PR-α → PR-β → PR-γ on `release/stg`, gated by Q1 and Q3 resolutions.
