---
report: red-team-failure-modes
plan: pr-62-split-audit-emitter-ship
date: 2026-05-24
---

# Red-Team: Failure Modes Ship-As-Is

12 silent prod-breakage modes.

## F-F-1 — Silent dropped-audit blackout (HIGH, phase-01)
DDoS: `queue_full_dropped`/`db_insert_failed`/`worker_restarted` increment in-process only. Operator sees flat rows, reads "attack stopped".
**Spec:** phase-01 sec 2.3 — pair counter inc with `tracing::warn!(target="audit_emitter")` for db_insert_failed + worker_restarted; `error!` once per panic with backtrace. Test `worker_panic_emits_error_log`.

## F-F-2 — Metrics invisible without scrape endpoint (HIGH, phase-04)
`metrics_snapshot()` test-only; no route registered.
**Spec:** phase-04 sec 2.6 `GET /api/audit/metrics` (admin-auth) returns snapshot JSON. Block phase-01 merge until signature agreed.

## F-F-3 — Phase 01 orphan API, silent no-op (CRITICAL, phase-01)
`set_audit_emitter()` lands with zero callers. Operator sets `enabled=true`; DB empty (phase 02/03 unmerged). False sense of audit during attack.
**Spec:** phase-01 sec 2.8 startup invariant — if `enabled=true` AND no RelayContext.audit_emitter AND no TxStore.audit_emitter, `warn!("audit_emitter enabled but no detection modules wired")`. Test `enabled_with_no_callers_logs_warning`.

## F-F-4 — Gate gamed by MockDatabase (MEDIUM, all)
Mock-only suite hits 90%+ without real INSERT. Schema drift surfaces in prod.
**Spec:** phase-01 sec 1.5 add `tests/audit_emitter_postgres_smoke.rs` via testcontainers, CI-required, excluded from gate numerator.

## F-F-5 — Panic-recovery test flake (MEDIUM, phase-01)
2s wall-clock timeout flakes on shared CI; gets `#[ignore]`d.
**Spec:** Rewrite with `tokio::test(start_paused=true)` + `time::advance(POST_PANIC_BACKOFF+1ms)` + blocking `recv()`.

## F-F-6 — ArcSwap torn read across `cfg.load()` (MEDIUM, phase-01)
`emit()` reads `enabled` then `window_secs` via separate loads. Hot-reload between -> mixed state. TTL drift.
**Spec:** phase-01 sec 2.6 first line `let cfg = self.cfg.load_full();`; all reads from same snapshot. Fuzz test N=1000.

## F-F-7 — DashMap Arc-String unbounded (HIGH, phase-01)
`Arc<(String, &static str)>` retained by in-flight tasks after gc. 1M unique IPs ~50MB+ live. Attacker-driven.
**Spec:** Key = `(u128, &static str)` Copy. IPv4 via `to_ipv6_mapped()`. Zero alloc hot path. `10k_unique_ips_fanout` asserts RSS delta < 5MB.

## F-F-8 — CI runner toolchain mismatch (HIGH, plan-wide)
Plan mandates rocky9 + rust 1.95.0; `.github/workflows/ci.yml` likely `ubuntu-latest` + stable.
**Spec:** New phase-00 pre-flight — audit ci.yml. If divergent, PR-0 updates workflow BEFORE phase 01.

## F-F-9 — Phase 04 blocked-by-02 serializes path (MEDIUM, phase-02/04)
`FeedStatusRegistry` from phase 02 blocks phase 04. Review stall -> weeks idle.
**Spec:** Move `FeedStatusRegistry` to phase 01 (`crates/waf-engine/src/intel_status.rs`, empty default). Phase 02 only populates. Phase-04 dep -> [1].

## F-F-10 — Doc drift via post-merge TODO (LOW, phase-04)
Tech-guide update promised post-merge; slips historically.
**Spec:** Doc diff IN same PR. PR template checklist: `[ ] docs/PRX-WAF-TechnicalGuide-{EN,VI}.md updated if API surface changed`.

## F-F-11 — Squash kills bisect granularity (LOW, plan-wide)
900-LOC phase squashed -> bisect cannot narrow bucket vs worker vs config.
**Spec:** Constraints row 1 — phases > 500 LOC keep up to 4 logical commits; squash only when <= 300 LOC.

## F-F-12 — Cargo workspace cycle risk (MEDIUM, phase-01)
If Database trait in waf-storage and waf-storage depends on waf-engine -> cycle on `cargo build`.
**Spec:** phase-01 Step 0 — `cargo tree -p waf-engine` + `-p waf-storage`. Document trait crate before code. Cycle = blocker.

---

## Cross-cutting

1. Each phase: observability checklist (log on inc/panic/reload/startup-config).
2. Per-phase testcontainers smoke, CI-required, excluded from gate %.
3. Paused-clock for all backoff/GC/window tests.
4. PR template doc-update checkbox; no deferred rows.

## Unresolved questions

- `tracing-appender` rate-limited logger in workspace? (F-F-1)
- `.github/workflows/ci.yml` toolchain pin? (F-F-8 blocker)
- Prometheus exposition wired, or JSON ceiling? (F-F-2)
- Loom/shuttle available, or N=1000 iter? (F-F-6)
