# FR-025 Phase 4: Async Ingest Pipeline

**Status**: Complete

**Scope**: Replace NoopAggregator with ScoringAggregator for bounded async signal ingestion. Map 12 Signal variants to Contributor types. Validate convergence and no regressions.

---

## Success Criteria

- [x] ScoringAggregator replaces NoopAggregator at boot
- [x] All 12 Signal variants mapped to Contributor types
- [x] Bounded MPSC channel + drop-with-warn metric implemented
- [x] Convergence property test passes (50ms timeout)
- [x] No .unwrap() introduced in Phase 4 code
- [x] Existing FR-010/011/012 tests still green (812 tests pass)

**Deferred (not blocking Phase 4 completion)**:
- [ ] FR-005 RiskBumpAction integration verified end-to-end (already uses aggregator, defer to Phase 5)
- [ ] Submit-throughput bench ≥50k/s (defer to Phase 5 performance tuning)

---

## Implementation Summary

### Files Created/Modified

| File | Purpose |
|------|---------|
| `crates/waf-engine/src/risk/ingest/mod.rs` | Facade + public API |
| `crates/waf-engine/src/risk/ingest/aggregator_impl.rs` | ScoringAggregator with bounded channel |
| `crates/waf-engine/src/risk/ingest/signal_to_contributor.rs` | Signal → Contributor mapping (12 variants) |
| `crates/waf-engine/src/risk/ingest/worker.rs` | Async worker: receive → map → apply |
| `crates/waf-engine/src/risk/ingest/metrics.rs` | IngestMetrics counters |
| `crates/waf-engine/src/risk/config.rs` | IngestConfig (channel_capacity) |

### Key Decisions

1. **Bounded Channel**: Default 65536 capacity prevents OOM on spike; drop-with-warn on overflow.
2. **Fire-and-Forget Submit**: Non-blocking; never blocks the request pipeline.
3. **Signal Weights**: Configurable per-signal contributor weight (12 variants mapped).
4. **Async Worker**: Supervised with exponential backoff restart on panic.
5. **No unwrap()**: All errors handled with `?` and `.context()`.

### Testing

- Convergence property test: 1000 concurrent submits → all contributors applied within 50ms
- Unit tests for signal mapping
- Integration: all 812 existing tests pass
- No regressions in FR-010, FR-011, FR-012 modules

---

## Architecture

```
Request pipeline:
  Signal (Risk, DDoS, Velocity, Anomaly, ...) 
    ↓
  [aggregator.submit(signal)] ← fire-and-forget
    ↓
  Bounded MPSC channel (65536 capacity)
    ↓
  [worker async loop]
    Signal → SignalWeights → Contributor
    ↓
  [store.apply(contributor)] → RiskState delta
```

---

## What's Next (Phase 5 & Beyond)

- **Phase 5**: Velocity Deltas L2 — time-windowed request rate (req/sec) scoring
- **Performance**: Bench submit-throughput ≥50k/s + optimize channel tuning
- **Integration**: End-to-end FR-005 RiskBumpAction with thresholds
- **Observability**: Ingest metrics dashboard + latency histograms

---

## Commits

- `f4298fc`: feat(risk): implement FR-025 Phase 4 rule deltas L1
- Related Phase 3: `e5d6212` feat(risk): implement FR-025 Phase 2 L0 reputation seed layer
- Related Phase 2: `381ac73` feat(risk): implement FR-025 Phase 1 cumulative risk scoring skeleton
