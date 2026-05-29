# Review Synthesis — main↔release/stg + open issues + stg HEAD quality

**Date:** 2026-05-27
**Branch context:** release/stg @ e8331bcb · main @ c4d852ab · common ancestor af10edb5
**Scope source:** `analysis/requirements.md` (WAF Mini Hackathon 2026)
**Reports:**
- `plans/reports/reviewer-1-260527-branch-divergence-audit.md`
- `plans/reports/reviewer-2-260527-open-issues-triage.md`
- `plans/reports/reviewer-3-260527-stg-head-quality-scan.md`

---

## 1. Headline

Three independent surveys converged. Iron-rule baseline on release/stg is clean (0 production `.unwrap`, 0 `todo!`, 0 `std::sync::Mutex`). Real gaps live in three buckets:

- **Bucket A — P0 gap-fill** (main has, release/stg lacks): CrowdSec circuit breaker (FR-039), DbBatchWriter + DB resilience (FR-032/039).
- **Bucket B — release/stg HEAD findings** (proactive): 2 CRITICAL trust-boundary bugs + 5 IMPORTANT defence-in-depth/auth gaps + 6 MODERATE.
- **Bucket C — Dashboard semantics + Admin Panel coverage**: #74 sub-items 4/5/6 (heatmap, stats_overview, category_of) + #60.X sub-issues (Honeypot, Risk Score, Challenge, TX Velocity, Relay, Geo, Reputation).
- **Bucket D — Deferred (escalate)**: #70/#75/#76 cluster Criticals (multi-node mock + election state machine — hard counter-condition per context.md:183), #95 SSL phases 03-06 (architectural path decision required).

Open PRs targeting `main` (#62, #98, #105, #106, #114) are **out-of-scope** of this command which loops on `release/stg`.

---

## 2. Solo-loop priority queue (release/stg → fix → release/stg)

All items in priority order. Each item: 1-file or small multi-file surgical fix; CI on release/stg; merge back to release/stg.

| # | ID | FR | Effort | One-line |
|---|---|---|---|---|
| 1 | **CR-1** XFF spoofing when `trusted_proxies` empty | FR-004/007/008/025 | ~30 LOC + tests | `ctx_builder/request_ctx_builder.rs:223` `is_empty` OR-branch trusts any peer when operator forgot to enumerate trusted proxies |
| 2 | **CR-2** Admin IP allowlist fails open on missing `ConnectInfo` | FR-031/032 | ~10 LOC + test | `waf-api/src/security.rs:207-218` defaults to 0.0.0.0 when extension absent → bypass |
| 3 | **#74.4** Heatmap `path_ranks` missing `rule_id IS NOT NULL` | FR-030 | 1-line SQL + test | `waf-storage/src/repo.rs:1527-1535` |
| 4 | **#74.5** `stats_overview` live-override fires for filtered queries | FR-030 | ~5 LOC | `waf-api/src/stats.rs:117-126` add `host_code/action` guard |
| 5 | **#74.6** Migrate inline CASE to `category_of()` | FR-030 | ~30 LOC | `waf-storage/src/repo.rs:1342-1390` (mirror callers at :1170/1255/1538) |
| 6 | **IM-2** SQLi `walk_json` iterative + depth gate | FR-013/020 | ~20 LOC | `waf-engine/src/checks/sql_injection_scanners.rs:58-90` (mirror `body_abuse_walker.rs:99`) |
| 7 | **IM-1** JSON redactor `walk()` iterative | FR-034 | ~20 LOC | `gateway/src/filters/response_json_field_redactor.rs:214-243` (mirror IM-2) |
| 8 | **IM-4** WS JWT re-validate on heartbeat | FR-029/032 | ~15 LOC | `waf-api/src/websocket.rs:115-176` tick check |
| 9 | **IM-5** WS upgrade `role == admin` gate | FR-029/032 | helper + 2 callsites | `waf-api/src/websocket.rs:115` + extract `require_admin_token` helper from `logs.rs:88` |
| 10 | **MO-3** TRAV-007 require `..` precondition | FR-015 | regex tweak + FP tests | `waf-engine/src/checks/dir_traversal.rs:42` |
| 11 | **A2** Port DbBatchWriter + DB resilience (`e7d7bf77`) | FR-032/039 | multi-file cherry-pick | bounded MPSC 10k + batch INSERT + retry_connect + health_check |
| 12 | **A1** Port CrowdSec circuit breaker (`6f39920a`) | FR-039 | multi-file cherry-pick | Closed/Open/HalfOpen state machine + AppSec wiring |
| 13 | **A3** CI llvm-cov error surface (`812f2ccd`) | infra | 1 script | `.github/scripts/coverage-check.sh` set -e capture |
| 14+ | **#60.X** Admin Panel sub-issues | FR-006/007/012/025-027/028/030/042 | per-sub-issue frontend | #60.5 Honeypot → #60.4 Risk Score → #60.1 Challenge → #60.3 TX Velocity → #60.2 Relay → #60.7 Geo → #60.6 Reputation |

### Ranking rationale

- **#1-2 first:** CRITICAL trust-boundary bugs reviewer-3 found. Direct correctness defects on a deployed branch — not theoretical. Smallest blast radius, immediate FR coverage.
- **#3-5 next:** dashboard correctness `#74.4/.5/.6` — judges see these directly during Attack Battle viz scoring (10 pts).
- **#6-7:** defence-in-depth on JSON walkers, both mirror an established iterative pattern already in repo.
- **#8-9:** admin-API auth surface tightening; matches existing `require_admin` pattern in `logs.rs`.
- **#10:** TRAV-007 false-positive risk (legit `/home/...` etc. flagged) — low blast but worth fixing before Battle.
- **#11-12:** cherry-pick A-bucket from main to fill P0 FR-032/039 gaps. Larger blast (multi-file) — gated after surgical items land.
- **#13:** CI infra cherry-pick.
- **#14+:** admin-panel frontend stack (#60.X) — different toolchain (React/AntD/Refine), still solo-loop eligible per sub-issue. Sequence per reviewer-2 ranking.

---

## 3. Deferred / Escalate

| Issue | Reason |
|---|---|
| #70 cluster join token | Hard counter-condition (`context.md:183`): multi-node mock + QUIC roundtrip. Reviewer-1 explicit reject. Alternative "delete `crypto/token.rs`" reverses prior user feature decision → needs user confirmation (rule §3). |
| #75 cluster Main step-down | Hard counter-condition: election state machine refactor + 3-node partition simulation. |
| #76 single-node bootstrap | Hard counter-condition: same election state machine as #75. |
| #95 native SSL phases 03-06 | Multi-day; architectural path A/B/C/D brainstorm gate. Cert renewal currently handled via certbot deploy hook (`context.md:191`). |
| #74.2 WS JWT in query param | UX/hygiene. Marginal Battle value. |
| #74.3 API rate limiter XFF | Admin-only surface. Marginal. |
| #74.7 admin per-route body limit | Defense-in-depth on already-capped surface (post-#71). |
| #60.6 IP Reputation UI | P1; degrades gracefully without UI. |
| IM-3 CSP unsafe-inline/unsafe-eval | NOT solo-loop — requires coordinated React/Vite bundler change to emit nonces. |

---

## 4. Merge conflict map (when release/stg → main eventually)

Three files where main + release/stg both modified the same surface — manual resolution required:

- `crates/waf-engine/src/rules/engine.rs` — main precompiles (`ce449e2e`), stg adds per-request `size_limit` cap (PR #73). **Keep BOTH** during merge.
- `crates/prx-waf/src/main.rs` — main wires DbBatchWriter + circuit breaker + log reload; stg modifies init order.
- `crates/waf-api/src/handlers.rs` — main adds POST /logs/level handler; stg adds plugin handlers.

Plus declaration-overlap in `waf-engine/src/{logging,crowdsec,checks}/mod.rs` — additive merges.

`role_tagger.rs:39` in main still calls bare `Regex::new` (no size_limit) — PR #73's defensive cap is not redundant with main's precompile because role_tagger is outside the precompile path. **Carry PR #73's cap forward independently.**

---

## 5. Unresolved questions surfaced by reviewers

1. **Deploy target — main or release/stg?** (reviewer-1) Drives eventual merge direction.
2. **FR-043/044/045 cluster BONUS pursuit?** (reviewer-1) If no, cluster wire-up from main does NOT port; #70/#75/#76 remain deferred indefinitely.
3. **PR #105 status** (reviewer-2): may already cover #60.5 Honeypot — verify before opening a duplicate.
4. **#70 alternative path** (reviewer-2): "delete `crypto/token.rs`" reverses a prior user feature decision. Per `review-audit-self-decision.md` Rule 3, requires explicit user confirmation.
5. **CR-1 fix direction** (reviewer-3): fail-secure (silently disable XFF) vs fail-loud (refuse startup). Production may prefer silent; hackathon judges may prefer loud.
6. **IM-3 CSP scope** (reviewer-3): `'unsafe-eval'` requirement source needs verifying before Vite config touch.
7. **IM-4/IM-5 centralisation** (reviewer-3): role checks at axum middleware vs inline per-handler?
8. **#74 sub-item batching** (reviewer-2): ship 74.4/74.5/74.6 as 3 PRs or 1 bundled SQL fix PR?
9. **c4d852ab commit title/body mismatch** (reviewer-1): "YAML skip" message but diff is cluster + plans — verify with author.
