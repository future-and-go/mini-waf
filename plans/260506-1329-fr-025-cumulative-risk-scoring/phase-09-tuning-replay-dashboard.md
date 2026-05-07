---
phase: 9
title: "Tuning Replay & Dashboard"
status: pending
priority: P2
effort: "4d"
dependencies: [1, 8]
---

# Phase 9: Tuning, Replay Harness, Dashboard

## Overview

Operationalize the scorer. Three deliverables:
1. **Replay harness** — re-score historical traffic from VictoriaLogs against tuned config; gate parameter changes on `<1% deviation` (NFR-RS-013).
2. **Live dashboard feed** — extend the existing FR-029/030 admin UI dashboard with risk score distribution, per-tier action rates, top contributors.
3. **Metrics + jitter** — Prometheus histograms for `waf_risk_eval_ms` per layer, ±2 jitter on `X-WAF-Risk-Score` header in production mode (anti-oracle), audit log fields (`risk_score`, `score_seed`, `contributors`, `dominant_rule`).

Optional: feature-flagged LSH fuzzy JA4 matching (FR-RS-041) — defer unless explicitly requested.

## Why P9 Last

Tuning depends on having a full feature set producing real scores. Dashboard depends on metrics being emitted across all phases. Replay harness depends on enough historical data to be statistically meaningful.

## Requirements

**Functional:**
- `risk-replay` binary (or `cargo xtask replay`) — reads VictoriaLogs export (NDJSON), re-runs scorer with config from disk, outputs distribution stats + diff vs. recorded scores.
- Replay gate: `--gate-percent 1.0` exits non-zero if score deviation across replay >1%.
- Prometheus metrics:
  - `waf_risk_score` histogram (label: `tier`).
  - `waf_risk_decision_total{decision}` counter.
  - `waf_risk_eval_ms{layer}` histogram.
  - `waf_risk_state_size` gauge (DashMap len per leg).
  - `waf_risk_dominant_rule_total{rule_id}` counter.
- Audit log: per-request VictoriaLogs entry includes `risk_score`, `risk_raw_score`, `risk_seed`, `risk_contributors[]`, `risk_dominant_rule`. **Piggyback** existing per-request log entry (Open Question #1 resolution).
- Dashboard tile: live histogram + top-10 dominant rules + ban table size.
- Header jitter: in production mode, `X-WAF-Risk-Score` is `score + jitter(-2..=+2)` deterministic per-request via `hash(now_ms ^ key)`. Bench/test mode: deterministic, no jitter.

**Non-functional:**
- Replay throughput ≥ 10k req/s on commodity hw (single-core).
- Dashboard latency: 1Hz refresh, no impact on request hot path.

## Architecture

```
crates/waf-engine/src/risk/replay/
├── mod.rs
├── harness.rs              # Driver: read NDJSON → for each, run scorer → diff
├── stats.rs                # distribution / deviation calc
└── reader.rs               # VictoriaLogs NDJSON reader (streaming)

crates/waf-engine/src/risk/metrics.rs    # global Prometheus registry handles
crates/waf-engine/src/risk/audit.rs      # piggyback fields injected into log

crates/waf-engine/src/risk/jitter.rs     # ±2 jitter helper
```

### Replay Harness CLI

```
$ cargo run --release --bin risk-replay -- \
    --logs /var/lib/victorialogs/export-2026-05-01.ndjson \
    --config configs/risk.yaml.tuned \
    --baseline configs/risk.yaml \
    --gate-percent 1.0 \
    --report /tmp/replay-report.json

Replay results: 1.2M requests
  Score deviation:  0.42% (within gate)
  Action drift:     Allow→Challenge: 0.08%, Challenge→Allow: 0.31%
  Top contributors: rule:sqli-001 (12k), anomaly:fp_conflict (8k), seed:tor (3k)
  EXIT 0
```

### Audit Log Fields (Piggyback)

Existing per-request log line gains:
```json
{
  "ts": "...",
  "method": "GET",
  "path": "/login",
  "ip": "1.2.3.4",
  "risk_score": 45,
  "risk_raw_score": 58,
  "risk_seed": 15,
  "risk_contributors": [
    {"kind": "rule", "id": "sqli-001", "delta": 40, "ts_ms": 17...},
    {"kind": "anomaly", "id": "fp_conflict", "delta": 20, "ts_ms": 17...}
  ],
  "risk_dominant_rule": "sqli-001",
  "risk_decision": "challenge"
}
```

## Related Code Files

**Create:**
- `crates/waf-engine/src/risk/replay/mod.rs`
- `crates/waf-engine/src/risk/replay/harness.rs`
- `crates/waf-engine/src/risk/replay/stats.rs`
- `crates/waf-engine/src/risk/replay/reader.rs`
- `crates/waf-engine/src/risk/metrics.rs`
- `crates/waf-engine/src/risk/audit.rs`
- `crates/waf-engine/src/risk/jitter.rs`
- `crates/waf-engine/src/bin/risk_replay.rs` (binary)
- `web/admin-ui/src/views/risk-dashboard.vue` (or existing dashboard route extension)
- `web/admin-ui/src/api/risk.ts`
- `crates/waf-api/src/risk_routes.rs` (admin API for dashboard)

**Modify:**
- `crates/waf-engine/src/risk/mod.rs` — `pub mod {replay, metrics, audit, jitter};`
- `crates/waf-engine/src/risk/config.rs` — `jitter:` section, `audit:` toggles.
- `crates/waf-engine/src/risk/scorer.rs` — emit metrics per layer, inject audit fields, apply jitter on response header.
- `crates/waf-engine/Cargo.toml` — add `[[bin]] name = "risk-replay"` if needed; `prometheus = "0.13"` (verify already present).
- `crates/waf-engine/src/logging/` — extend per-request log struct with risk fields.
- `web/admin-ui/src/router.ts` — register risk route.
- `docs/deployment-guide.md` — replay runbook, dashboard ops.

## Implementation Steps

1. **Metrics scaffolding.** Global Prometheus registry handles in `risk/metrics.rs`. Bump per layer (seed, rule, anomaly, velocity, decay, threshold) via `Histogram::observe(elapsed.as_micros())`.
2. **Audit fields.** Extend logging struct (find where per-request entry built — likely `crates/waf-engine/src/logging/`). Add risk fields (Option types — None when scorer disabled).
3. **Jitter.** `jitter.rs` — `pub fn apply(score: u8, key_hash: u64, now_ms: i64) -> u8` deterministic, uses xxhash. Disabled in test/bench builds via cfg.
4. **Replay harness.** `reader.rs` streams NDJSON via `tokio_stream`. `harness.rs` runs scorer for each entry; collects (recorded_score, replayed_score) pairs. `stats.rs` computes distribution, deviation %, action-drift cells.
5. **Replay binary.** `bin/risk_replay.rs` — clap CLI, calls harness, writes report JSON, exits non-zero on gate breach.
6. **Dashboard backend.** `crates/waf-api/src/risk_routes.rs` — `/api/risk/stats`, `/api/risk/top-rules`, `/api/risk/ban-table`. Read from in-process metrics + RiskStore.
7. **Dashboard frontend.** Vue3 view: histogram (Chart.js or built-in), top-10 rules, ban table size, refresh 1Hz.
8. **Tests.**
   - Replay harness: synthetic NDJSON of 10k entries → expected distribution.
   - Gate breach: tune config to deviate >1% → exit non-zero.
   - Jitter: same input → same output (deterministic); range stays within ±2.
   - Audit fields present on every log entry when scorer enabled.
9. **Bench.** Replay throughput ≥ 10k req/s.
10. **Compile gates + smoke.**

## Common Pitfalls

- **Replay re-uses live store** → contaminates production state. Replay harness MUST use a fresh in-memory store, never touch shared Redis.
- **Jitter applied to internal score → tier multiplier breaks** — apply ONLY to egress header, NEVER to internal `clamped_score`.
- **Dashboard polling at 100Hz** — fixed 1Hz; backend caches stats in `ArcSwap<DashboardStats>` updated by background task.
- **Audit log payload size explodes** — cap `risk_contributors[]` to 8 most-recent (matches SmallVec inline cap).
- **VictoriaLogs export schema drift** — pin reader to schema version; bump on field changes.

## Success Criteria

- [ ] All Prometheus metrics emitted; visible in `/metrics` endpoint.
- [ ] Audit log entries include risk fields.
- [ ] Replay harness runs end-to-end, produces report.
- [ ] Replay gate fails on >1% deviation.
- [ ] Dashboard view live; 1Hz refresh; no hot-path impact.
- [ ] Jitter range ±2, deterministic in test mode.
- [ ] No `.unwrap()` introduced.
- [ ] Binary `risk-replay` builds with `--release`.

## Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| Replay contaminates prod state | High | Isolated in-memory store; assertion in harness |
| Jitter breaks bench reproducibility | Medium | Disabled in test/bench builds via cfg |
| Audit log payload size impacts ingest | Medium | Cap contributors to 8; document VictoriaLogs storage growth |
| Dashboard endpoint becomes attack vector | Medium | Auth-gated (admin UI session); rate-limited |
| Replay harness too slow on 24h log | Medium | 10k/s gate; parallelize reader if needed |

## Deferred (NOT this phase)

- **FR-RS-041 LSH fuzzy JA4** — feature-flagged hook only; full implementation a separate ticket. Adds `rensa` dep + L3 latency layer.

## Verify

```bash
cargo build --release --bin risk-replay
cargo test -p waf-engine risk::replay
cargo bench -p waf-engine --bench risk_skeleton -- replay
# Live smoke
curl -s http://localhost:16880/metrics | grep waf_risk
# Dashboard
open http://localhost:16827/ui/risk
```
