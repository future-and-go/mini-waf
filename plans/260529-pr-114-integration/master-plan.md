# PR #114 Integration — Master Plan

**Date:** 2026-05-29
**Target:** release/stg @ `5bc0616bc`
**Source:** colleague PR #114 (`feat/admin-panel-phase1`, base=main)
**Authority:** user pref `[[feedback-production-ready-no-stubs]]` — production-grade, no stubs, no temp fixes; missing features in `analysis/requirements.md` scope CAN be written; out-of-scope work stays deferred.

## Decisions

| Q | Decision | Rationale |
|---|---|---|
| Q1 Risk page seq | **Port audit_emitter scaffold (PR-0) + write the relay/tx_velocity callers ourselves** — production-ready data path | "không tạm bợ" → empty-state banner rejected. Wait-for-#105 unbounded. Port + complete. |
| Q2 Stub handlers (C1) | **Wire to live stores** (no 501 placebos, no `success:true` no-ops) | Operator deception is the failure mode user said "không tạm bợ" against. |
| Q3 I4 cluster trust | **Document trust model + add `X-Forwarded-By` audit header**; defer crypto-grade re-issue | I4 is pre-existing on stg (carry-over from #138 wave), NOT introduced by PR #114. Out-of-scope for "integrate PR #114". Trust-doc + audit header is the production-grade hardening that's in scope. |
| Q4 FE 250-LOC | **Split ALL FE pages > 250 LOC into `components/` subtrees** | rules.md line 12 mandates ≤250 LOC. Production discipline. 8 pages affected. |
| Q5 #60.6 IP Reputation | **Ship as PR-ε after PR-γ** — FR-042 in scope, missing from #114, user authorised "thiếu tính năng thì viết thêm" | Separate PR for review-ability; minimal blast radius. |

## Hard scope guard (DO NOT touch)

- Cluster Criticals #70/#75/#76 — multi-node mock required, deferred.
- Native TLS phases 03–06 — deferred per #95 prior reviewer-2 ranking.
- Regex precompile rewrite — conflicts with stg's PR #73 size_limit cap.
- Cluster end-to-end wire-up — deferred.
- Anything from PR #114 that REVERSES wave-3 hardening (XFF, admin allowlist, JSON walkers, WS JWT, TRAV-007, charset reject, etc.) — skip the file entirely.

## Pre-merge fixes applied to EVERY affected slice

1. **C1 — wire stubs to real stores.** No `success:true` no-ops. Each mutation handler reads from / writes to the source-of-truth (DB or YAML) and returns the post-state.
2. **C2 — typed serde + axum `RequestBodyLimit`.** Every PUT handler deserialises the body into a typed struct; reject malformed with 400. Body size cap = 256 KiB per route (existing `RequestBodyLimit` middleware extended).
3. **C3 — `tunnels.protocol` widened + CHECK constraint.** `VARCHAR(8)` (covers `tcp`/`udp`/`ws`/`quic`/`http`/`grpc`) + `CHECK (protocol IN ('tcp','udp','ws','quic','http','grpc'))`. API boundary enums + reject unknown.
4. **I1 — sidecar.rs file SKIPPED entirely** per reviewer-3's "already on stg, source REVERTS" classification. `Duration::from_mins` regression dies with the file skip.
5. **I5 — `list_tunnels` JSON envelope** — keep old `{tunnels: [...]}` key as a deprecation alias for one release; add new `{success, data, total}` envelope alongside. Documented in PR body.
6. **C4 — `reload_from_registry`** — implement registry-driven reload (rebuild `CustomRulesEngine` from `registry.rules`). No "scaffold + re-title" shortcut.
7. **I2 — `sidecar.spawn()`** — file skipped; not our problem.
8. **I3 — `set_log_level` cooldown** — `compare_exchange` on the timestamp atom; reject 429 on conflict.
9. **I7 — blocking `fs::read_dir` in async** — wrap in `tokio::task::spawn_blocking` in `apply_sync_response_sync`.
10. **I8 — `challenge_preview` XSS-defense-in-depth** — HTML-escape `title` and `message` before `format!`. Use `html_escape` crate (or hand-roll if dep budget says no).
11. **I9 — `Database::connect` health-check loop** — accept a `Option<tokio::sync::watch::Receiver<()>>` shutdown signal; CLI commands pass `Some(rx)` and signal on drop.
12. **I10 — YAML parse error convention** — GET → fall back to defaults + WARN log + emit a `config_parse_errors_total` metric; PUT → reject 400. Documented.
13. **M1 — role-based authz on new mutation endpoints** — add `require_admin` extractor (already in `auth.rs` via wave-3); stack on PUT/POST/DELETE/PATCH for all new routes.
14. **M2 — geo rule `next_id` race** — process-wide `tokio::Mutex` around read-modify-write OR use UUID as identifier. Prefer UUID for forward-compat.
15. **M3 — `patch_geo_rule` whitelist drops user fields** — reject unknown PATCH keys with 400 + error body listing accepted keys.
16. **M4 — sidecar restart loop** — file skipped.
17. **M5 — `lookup_ip` deceptive payload** — return `503` + `{status: "geoip_unavailable"}` envelope.
18. **M6 — `db_batch_writer` event loss** — already-on-stg via #137; add `dropped_events_total` counter + Prometheus exposition; switch `TrySendError::Full` to bounded backpressure (`send_timeout(100ms)`) so under sustained burst the gateway visibly slows rather than silently drops audit.
19. **M8 — coverage ≥ 90%** — add integration tests per new `_api.rs` module under `crates/waf-api/tests/<name>_api.rs`. YAML round-trip, validation rejects, auth gate, RBAC.
20. **M9 — clippy lints** — pre-scan per `[[pattern-clippy-cherry-pick-lint-catalogue-wave3]]` before push. Cap CI iters at 2.
21. **M10 — `LAST_LOG_LEVEL_CHANGE_MS` clock-jump** — use `std::time::Instant` (monotonic).
22. **M11 — `geo-rules.yaml` path mismatch** — pick `configs/geo-rules.yaml` (consistent with other config-vs-rules split); fix doc.

## PR sequence (6 PRs)

### PR-0 — `feat(engine): audit emitter core + integration tests`

Port PR #105 scaffold + complete the outstanding tests. **No callers wired by PR-0** — the engine init code will log a warning until PR-β2 lands.

- **Source:** PR #105 commits (`feat/audit-emitter-core-issue-60-a`).
- **Files:** 14 (per #105 file list).
- **Add for production-ready:**
  - `crates/waf-engine/tests/audit_emitter_unit.rs` — 16 integration tests (disabled fast-path, channel-full rollback, hot-reload, rule_id grammar drop, global limit, atomic reserve contention, orphan-API warn, sanitiser boundary, etc.)
  - `crates/waf-engine/tests/audit_emitter_cardinality.rs` — single-IP burst, 10k fan-out, RSS-delta < 5 MB, mixed burst, max-keys eviction.
  - `crates/waf-engine/tests/audit_emitter_postgres_smoke.rs` (excluded from coverage gate per BP8) using `testcontainers`.
- **CI:** rust-toolchain pinned to 1.91 (per PR #105 .github/workflows/ci.yml diff).
- **Coverage gate:** ≥ 90% on `audit_emitter/` module.
- **FR delivered:** prerequisite for FR-025/026/027 risk-scoring; foundation for #60.4.

### PR-α — `feat(api,ui): tier policies + DDoS + access lists editors`

P0 mandatory; no audit_emitter dependency.

- **BE:** `tier_policies_api.rs` (152), `ddos_api.rs` (138), `access_lists_api.rs` (181) + integration tests + RBAC gate + typed serde + body limit.
- **Config:** `configs/tier-policies.yaml`, `configs/ddos.yaml`.
- **FE:** `pages/tier-policies/` (split: index 250 + `components/RuleEditor.tsx` + `components/PolicyList.tsx`), `pages/ddos-protection/` (split: index 250 + 3 components), `pages/access-lists/` (split: index 250 + `IpListCard` already extracted + 2 more components).
- **FR:** FR-002, FR-005, FR-008, FR-036, FR-037, FR-038.
- **Pre-merge fixes:** M1, M9, M11, M7.
- **C1 wire:** `delete_ban_entry` — read from `ddos.runtime_ban_store` (Arc<DashMap<IpAddr, BanEntry>>), remove the entry, persist via `engine.flush_ban_store()`. Return `{removed: bool, ip}`.

### PR-β1 — `feat(api,ui): challenge engine + relay intel + device-fp + geo` (P1 minus risk)

P1 intelligence subset that does NOT need audit_emitter rows.

- **BE:** `challenge_api.rs` (177), `relay_api.rs` (119), `device_fp_api.rs` (161), `geo_api.rs` (159).
- **Config:** `configs/relay.yaml`.
- **FE:** 4 pages + components subtree per Q4 decision.
- **FR:** FR-006, FR-007, FR-010, FR-011, FR-041.
- **Pre-merge fixes:** C1 (refresh_relay_intel, test_relay), C2 (4 PUTs), I8 (challenge_preview escape), I10 (YAML convention), M1, M2 (geo next_id → UUID), M3, M5, M9, M11.

### PR-β2 — `feat(api,engine,ui): risk scoring + audit emitter call sites in relay/tx_velocity`

P1 risk + writing the missing PR-B/C call sites ourselves (user-authorised production-ready path).

- **BE:** `risk_api.rs` (188) + risk store persistence + audit_emitter call sites:
  - `crates/waf-engine/src/checks/relay/detector.rs` — emit `BOT-RELAY-001` / `BOT-XFF-001` / `BOT-TOR-001` per the rule_id grammar contract.
  - `crates/waf-engine/src/checks/tx_velocity/{detector,mod}.rs` — emit `TX-SEQ-001`/`TX-WITHDRAW-001`/`TX-LIMIT-001` per detection.
- **FE:** `pages/risk-scoring/` (split: 694 → index 250 + ≥3 components).
- **FR:** FR-025, FR-026, FR-027.
- **Pre-merge fixes:** C1 (credit_risk_actor, clear_risk_actor — wire to risk store), C2, M1, M9.
- **Depends on:** PR-0 (audit_emitter core).

### PR-γ — `feat(api,ui,storage): response filtering + sensitive patterns + plugins + tunnels + migration 0017`

Hygiene + admin-panel-gap.md bugs.

- **BE:** `handlers.rs::patch_sensitive_pattern` (hand-port), `plugins.rs` response-shape, `tunnels.rs` + `protocol` field, migration `0017_tunnel_protocol.sql` (with C3 widening), repo updates.
- **FE:** 4 pages + components subtree.
- **FR:** FR-022, FR-033, FR-034, FR-035.
- **Pre-merge fixes:** C2, C3, I5 (deprecation alias for old envelope), M1, M9.

### PR-δ — `docs(cluster): document peer trust model + add X-Forwarded-By audit header`

Q3 decision — cheap, in-scope.

- `docs/cluster-protocol.md` — section "Replay Trust Model" stating "any mTLS-authenticated peer is fully trusted to forge admin-API requests via `replay_request`. Compromise of a worker keypair = full admin compromise. Operators MUST rotate worker keypairs on suspected compromise."
- `crates/waf-cluster/src/cluster_forward.rs` — strip headers list extended; add `X-Forwarded-By: <node_id>` injected at replay time; log `info!(target: "audit", peer_node_id, action, "replay request from cluster peer")`.
- Test: `tests/cluster_forward_audit_header.rs` — assert header present on every forwarded request.

### PR-ε — `feat(api,ui): IP reputation editor (#60.6, FR-042)`

User-authorised in-scope feature add (not in PR #114).

- **BE:** new `reputation_api.rs` with CRUD over reputation list (≈140 LOC).
- **Storage:** new migration `0018_reputation_list.sql` + repo helpers.
- **FE:** new `pages/reputation/` (split if > 250).
- **FR:** FR-042.

## Execution order

PR-0, PR-α can start in parallel (independent surfaces).
PR-β1 starts after PR-α merges (shared wiring lines in `server.rs`).
PR-β2 starts after PR-0 merges.
PR-γ starts after PR-β1 merges (shared FE i18n + nav).
PR-δ starts after PR-γ merges.
PR-ε last.

Realistically: serial loop with each PR landing before next opens (avoid PR-stack conflicts). Target: 1–2 PRs per day; full wave ≈ 4–5 days.

## Open follow-ups (not blocking)

- Forward-port `c42e8e64e` lint deltas to wave-3 files as XS PRs if reviewer-2 confirms they're pure clippy.
- Verify S12 (`coverage-check.sh` + INET test removal) — likely small cherry-pick if not on stg.
- Verify S14 (`c4d852ab0` waf-api rule-scan filter) — likely small cherry-pick.
- File issue for I4 crypto-grade re-issue (post-Battle hardening).
