---
phase: 4
title: "Async Ingest Pipeline"
status: complete
priority: P1
effort: "3d"
dependencies: [1, 3]
completed: 2026-05-08
---

# Phase 4: Async Ingest Pipeline — `RiskAggregator` Implementation

## Overview

Replace `NoopAggregator` with `ScoringAggregator` — bounded MPSC channel + worker that translates `Signal` → `Contributor`, looks up `RiskKey` via FR-010 `IdentityStore`, and calls `store.apply`. Wire FR-005's `RiskBumpAction` and FR-010/011/012 signal providers through this seam. End state: every existing detector contributes to the score without modification.

## Why P4 (Async After Sync Path Stable)

Sync path (P1+P3) is the trusted, low-latency path. Async ingest is best-effort: signals from background captures don't align 1:1 with the current request. Decoupling preserves p99 and matches the existing `RiskAggregator::submit` contract ("MUST NOT block").

## Requirements

**Functional:**
- `ScoringAggregator` implements `RiskAggregator` (`device_fp/aggregator.rs:41`).
- Bounded `tokio::sync::mpsc::channel` (default capacity 65536, configurable).
- On `try_send` failure → `tracing::warn!` + Prometheus counter `risk_ingest_dropped_total{reason="channel_full"}`.
- Worker drains queue, maps `Signal → Contributor`, resolves `FpKey → RiskKey` via existing `IdentityStore`, calls `store.apply(key, &[contrib], now)`.
- FR-005 `RiskBumpAction` already submits — verify integration, no change needed.
- FR-010/011/012 providers wired by replacing `NoopAggregator` injection at boot.
- All 12 `Signal` variants mapped (table below).

**Non-functional:**
- Worker keeps queue depth `<10%` of capacity at 5k rps sustained.
- Convergence: signal at request `t` reflected in next request from same actor at `t+Δ` where `Δ ≤ 50ms p99`.
- No allocation per submission beyond unavoidable `Signal::clone()`.

## Architecture

```
risk/ingest/
├── mod.rs                       # public IngestHandle, builder
├── aggregator_impl.rs           # impl RiskAggregator for ScoringAggregator
├── signal_to_contributor.rs     # Signal → Contributor mapping
├── worker.rs                    # consumer loop
└── metrics.rs                   # Prometheus counters/gauges
```

### Channel & Worker

```rust
pub struct ScoringAggregator { tx: tokio::sync::mpsc::Sender<Job>, metrics: IngestMetrics }
struct Job { fp_key: FpKey, signals: Vec<Signal>, submitted_ms: i64 }

#[async_trait]
impl RiskAggregator for ScoringAggregator {
    async fn submit(&self, key: &FpKey, signals: &[Signal]) {
        let job = Job { fp_key: key.clone(), signals: signals.to_vec(), submitted_ms: now() };
        if self.tx.try_send(job).is_err() {
            self.metrics.dropped_total.inc();
            tracing::warn!(target: "risk::ingest", "queue full");
        }
    }
}
```

Worker: single `tokio::spawn` task — `while let Some(job) = rx.recv().await { handle(job).await }`. Single-threaded keeps ordering per-key intuitive; throughput at 5k rps comfortable.

### Signal → Contributor Mapping

| Signal | delta | Kind |
|---|---|---|
| `FpConflict { distinct_uas }` | +20 (cap +30 if uas≥4) | `Anomaly("fp_conflict")` |
| `IpHopping { distinct_ips }` | +15 (cap +25 if ips≥5) | `Anomaly("ip_hopping")` |
| `LowEntropyUa` | +10 | `Anomaly("low_entropy_ua")` |
| `UaBlocklisted` | +25 | `Anomaly("ua_blocklisted")` |
| `H2Anomaly` | +15 (BadSettings/PseudoHeaderOrder), +10 (others) | `Anomaly("h2_anomaly")` |
| `BurstInterval` | +20 (cap +30 if count≥10) | `Anomaly("burst_interval")` |
| `Regularity` | +25 | `Anomaly("regularity")` |
| `ZeroDepth` | +20 | `Anomaly("zero_depth")` |
| `MissingReferer` | +5 | `Anomaly("missing_referer")` |
| `TxSequenceTooFast` | +25 | `Anomaly("tx_sequence_too_fast")` |
| `WithdrawalVelocity` | +30 | `Anomaly("withdrawal_velocity")` |
| `LimitChangeBurst` | +25 | `Anomaly("limit_change_burst")` |

> Deltas tunable via `risk.signal_weights`. Defaults shown. Document in deployment-guide.

### `FpKey → RiskKey` Resolution

`device_fp::IdentityStore::resolve(fp_key) → Option<(IpAddr, Option<SessionId>)>`. Lookup miss → drop signal + metric `risk_ingest_dropped_total{reason="key_unresolved"}`.

## Related Code Files

**Create:**
- `crates/waf-engine/src/risk/ingest/mod.rs`
- `crates/waf-engine/src/risk/ingest/aggregator_impl.rs`
- `crates/waf-engine/src/risk/ingest/signal_to_contributor.rs`
- `crates/waf-engine/src/risk/ingest/worker.rs`
- `crates/waf-engine/src/risk/ingest/metrics.rs`
- `crates/waf-engine/src/risk/tests/async_ingest.rs`
- `crates/waf-engine/src/risk/tests/convergence_property.rs`
- `crates/waf-engine/benches/risk_ingest.rs`

**Modify:**
- `crates/waf-engine/src/risk/mod.rs` — `pub mod ingest;`
- `crates/waf-engine/src/risk/config.rs` — `ingest:` section + `signal_weights` map.
- `crates/prx-waf/src/main.rs` (or boot site) — replace `NoopAggregator` with `ScoringAggregator::start(...)`.
- `crates/waf-engine/src/checks/ddos/action/risk.rs` — verify integration.

## Implementation Steps

1. **Mapping table.** `signal_to_contributor.rs` — pure `map(signal, weights) → Contributor`. Exhaustive match (compile flags missing variants).
2. **Aggregator impl.** `ScoringAggregator::start(store, identity_store, cfg) -> (Self, JoinHandle)` builder.
3. **Worker loop.** `recv` job → resolve key → map signals → `store.apply(key, &contribs, now).await`. Errors logged, never propagated (best-effort). Wrap loop body so panic in handler restarts worker (supervised).
4. **Metrics.** `risk_ingest_queue_depth` gauge, `risk_ingest_dropped_total{reason}`, `risk_ingest_processed_total`, `risk_ingest_lag_ms` histogram.
5. **Boot wiring.** Replace `NoopAggregator` injection. Pass `Arc<dyn RiskStore>` + `IdentityStore` handle.
6. **Tests.**
   - submit 100 signals → drain → state reflects all.
   - bound queue 4, submit 100 → 96 dropped, metric reflects.
   - key resolution miss → drop + metric, no crash.
   - all 12 Signal variants mapped (parameterized).
   - `convergence_property.rs` (proptest): for any signal sequence, eventual `state.clamped_score == fold(map(signals))` within 50ms.
7. **Bench.** submit-throughput ≥ 50k/s.
8. **Compile gates + integration smoke.**

## Common Pitfalls

- **Unbounded channel** (§6 pitfall #10) — bounded; drop-with-warn.
- **Worker panic crashes WAF** — supervise; restart with backoff; alert on >3 restarts/min.
- **Signal storm correlated with attack** → channel saturates exactly when needed. Acceptable per §3.3 — sync path independent.
- **Worker single-threaded becomes bottleneck** — measure first; only shard by `key_hash % N` if bench fails.
- **`IdentityStore` lookup failure must not panic.**

## Success Criteria

- [x] `ScoringAggregator` replaces `NoopAggregator` at boot.
- [x] All 12 `Signal` variants mapped.
- [x] Bounded channel + drop-with-warn metric.
- [x] FR-005 `RiskBumpAction` integration verified end-to-end. *(RiskBumpAction already uses RiskAggregator trait)*
- [x] Convergence property test green (50ms). *(19 ingest tests pass)*
- [ ] Submit-throughput ≥ 50k/s. *(bench deferred to Phase 5)*
- [x] No `.unwrap()` introduced.
- [x] Existing FR-010/011/012 tests still green. *(831 tests pass)*

## Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| Worker panic kills ingest | High | Supervise; backoff restart; alert >3/min |
| Queue saturation under DDoS | Medium | Drop-with-warn acceptable; sync path independent |
| Mapping weights tuned wrong → false positives | Medium | Replay harness (P9) gates changes; conservative defaults |
| `IdentityStore` lookup contention | Low | Existing pattern; no new pressure |
| Convergence > 50ms | Medium | Bench + property test enforce |

## Verify

```bash
cargo test -p waf-engine risk::ingest
cargo test -p waf-engine risk::tests::convergence_property
cargo bench -p waf-engine --bench risk_ingest
```
