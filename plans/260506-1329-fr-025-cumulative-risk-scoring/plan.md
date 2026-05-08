---
title: "FR-025 Cumulative Risk Scoring (Production)"
description: "Per-actor cumulative risk score (0–100) over `{IP + device_fp + session}` triple. Layered pipeline + event-sourced state. Drives FR-027 Allow/Challenge/Block gate and FR-028 honeypot."
status: pending
priority: P1
branch: "main"
tags: ["security", "fr-025", "fr-026", "fr-027", "fr-028", "production-ready", "risk-scoring"]
blockedBy: []
blocks: []
created: "2026-05-06T06:29:51.807Z"
createdBy: "ck:plan"
source: skill
---

# FR-025 Cumulative Risk Scoring (Production)

## Overview

Build the cumulative scorer that turns existing detection signals (FR-005 DDoS, FR-010 device-fp, FR-011 anomaly, FR-012 velocity, rule engine) into a single per-actor 0–100 risk score, persisted across requests, evaluated against configurable thresholds (Allow / Challenge / Block), and enriched by canary-honeypot pinning.

**This is the missing brain.** All upstream detectors already emit `Signal` variants into `RiskAggregator` — the current impl is `NoopAggregator`. Score the signals, persist the state, gate the action.

## Acceptance (verbatim from `analysis/requirements.md`)

- **FR-025** Per `{IP + device_fp + session}` — does NOT reset per request.
- **FR-026** Increases on rule match, failed challenge, anomaly, suspicious ASN, fp conflict. Decreases on successful challenge, sustained normal.
- **FR-027** Configurable thresholds: `<30 Allow`, `30–70 Challenge`, `>70 Block`.
- **FR-028** Canary path → auto max risk + IP block.

## Source Documents (read first)

- `plans/reports/brainstorm-260506-1310-fr-025-cumulative-risk-scoring.md` — design rationale, patterns, pitfalls (THIS PLAN'S BLUEPRINT).
- `plans/reports/spec-260430-1709-risk-score-requirements-and-tech-spec.md` — FR-RS-001..125 detailed spec.
- `plans/reports/research-260430-1639-risk-score-design-brainstorm.md` — earlier exploration.
- `analysis/requirements.md` — FR-025/026/027/028 acceptance.
- Existing seams: `crates/waf-engine/src/device_fp/aggregator.rs`, `device_fp/signal.rs`, `device_fp/identity/`, `checks/ddos/{store,action}/`, `checks/tx_velocity/`.

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [Skeleton & Store Trait](./phase-01-skeleton-store-trait.md) | Complete (100 %) |
| 2 | [Reputation Seed L0](./phase-02-reputation-seed-l0.md) | Complete (100 %) |
| 3 | [Rule Deltas L1](./phase-03-rule-deltas-l1.md) | Complete (100 %) |
| 4 | [Async Ingest Pipeline](./phase-04-async-ingest-pipeline.md) | Complete (100 %) |
| 5 | [Anomaly & Velocity L2](./phase-05-anomaly-velocity-l2.md) | Complete (100 %) |
| 6 | [Canary Honeypot FR-028](./phase-06-canary-honeypot-fr-028.md) | Complete (100 %) |
| 7 | [Redis Cluster Backend](./phase-07-redis-cluster-backend.md) | Complete (100 %) |
| 8 | [Challenge Credit FR-006](./phase-08-challenge-credit-fr-006.md) | Pending |
| 9 | [Tuning Replay & Dashboard](./phase-09-tuning-replay-dashboard.md) | Pending |

## Phase Sequencing & Gates

- P1 → P2: P1 must compile and ship `X-WAF-Risk-Score` header (BG-01) before adding seed.
- P2 → P3: Reputation seed must be hot-reloadable and bench-verified (<100µs).
- P3 → P4: Rule deltas in sync path before async ingest (sync deltas are trusted; async is best-effort).
- P4 → P5: Async pipeline absorbs background signals before adding sync per-request anomalies.
- P5 → P6: Lifecycle test (rise → decay) green before honeypot pinning.
- P6 → P7: Single-node memory backend feature-complete before adding cluster.
- P7 → P8: Cluster green before challenge credit (challenge state must persist cluster-wide).
- P8 → P9: Full feature set before tuning replay & dashboard.

## Cross-Cutting Invariants (NEVER violate)

1. **Triple key takes MAX** across `{ip, fp, session}` views — never SUM.
2. **Integer arithmetic only** — `(score * mult_x100 + 50) / 100`. No `f32` on the hot path (BG-10 determinism).
3. **Per-request raw delta clamp** to `[0, 100]` BEFORE tier multiplier.
4. **MAX_DECAY = 50** — fully-decayed key retains 50 points evidence floor.
5. **Bounded MPSC** for async ingest (default 65536) — drop-with-warn on overflow + Prometheus counter.
6. **Score state shared via `Arc<RwLock<RiskState>>`** across three DashMap indices — single state, three lookups.
7. **`store.apply` returns post-update state** — sync hot path uses returned value, not a follow-up read.
8. **Cookie name `X-WAF-Sid`** signed with HMAC; never collide with backend cookie names.
9. **Whitelist short-circuit FIRST** in seed layer — bypass all subsequent layers.
10. **Reset is atomic** (`reset_all` exclusive lock ≤50ms) — never half-cleared store.
11. **HMAC secret persisted** to file; regenerated only on first boot (NOT on `reset_state`).
12. **No `.unwrap()` / `.expect()` in production** (CLAUDE.md Iron Rule #1) — use `?` + `anyhow::Context`.
13. **Cargo features:** `redis-store` (mirrors existing FR-005/FR-010 pattern). Memory backend default.
14. **Pre-clamp `raw_score`** retained in audit log — runtime decision uses clamped value.

## Performance Budgets (NFR-RS-001 / NFR-RS-013)

| Layer | p99 budget | Where measured |
|-------|-----------|----------------|
| L0 reputation seed | ≤ 100µs | criterion `seed_lookup` |
| L1 rule deltas (already-evaluated) | ≤ 50µs (fold only) | criterion `score_fold` |
| L2 anomaly + velocity | ≤ 1ms | criterion `anomaly_full` |
| L3 decay | ≤ 50µs | criterion `decay_apply` |
| Threshold gate | ≤ 10µs | criterion `decide` |
| **Total risk-eval contribution** | **≤ 3ms p99 @ 5k rps** | k6 + Prometheus histogram `waf_risk_eval_ms` |

## Configuration Schema (top-level YAML, loaded via existing config crate)

```yaml
risk:
  enabled: true
  store:
    backend: memory          # memory | redis
    ttl_idle_sec: 1800       # 30 min — never per-request reset
    redis:
      key_prefix: "waf:risk:"
      apply_timeout_ms: 100
  thresholds:
    t_allow: 30              # <30 Allow
    t_block: 70              # >70 Block; [30,70] Challenge
  decay:
    half_life_sec: 600
    max_decay: 50            # MUST be 50; do not relax
  session:
    cookie_name: "session"   # configurable per-host
    fallback_cookie: "X-WAF-Sid"
    hmac_secret_path: "/etc/prx-waf/risk-hmac.key"
  canary:
    paths: ["/admin-test", "/api-debug"]
    ban_ttl_sec: 3600
  ingest:
    queue_size: 65536
  jitter:
    egress_score_pm: 2       # ±2 jitter on X-WAF-Risk-Score header in production mode
```

## Dependencies

- **Internal seams (already built):** `device_fp::RiskAggregator`, `device_fp::Signal`, `device_fp::IdentityStore`, `checks::ddos::store::CounterStore`, `checks::ddos::action::RiskBumpAction`, `checks::Check`, `waf-common::WafDecision`, `checks::tx_velocity` session keying, `BlockIpRepo` (FR-008 dynamic blacklist).
- **External crates (already in workspace):** `dashmap`, `parking_lot`, `arc-swap`, `tokio`, `async-trait`, `anyhow`, `serde`, `tracing`, `criterion` (dev), `notify` (hot-reload).
- **New crates (P7+):** `hmac`, `sha2` (P8 challenge tokens). No new deps in P1–P6.

## Open Questions (defer; recorded for ops & integration)

1. **TOCTOU race in `apply()` (Phase 1 code review)** — Between triple-index lookup and write lock, two concurrent requests could both miss and create separate states. Deferred to Phase 7 (Redis cluster backend provides atomic compare-and-swap). Mitigation: in-memory backend only runs single-node, collision probability low.
2. Audit log integration — piggyback per-request VictoriaLogs entry vs. dedicated risk topic? (Recommend piggyback.)
3. Session cookie discovery — per-host config vs. autodetect? (Recommend per-host config + default list fallback.)
4. HMAC secret rotation cadence — manual via runbook only (recommended); never auto-rotate.
5. LSH fuzzy JA4 (FR-RS-041) — defer to P9, feature-flagged.
6. `X-WAF-Risk-Score` jitter (±2) in production mode vs. deterministic for benchmarks — defer wiring to P9.
