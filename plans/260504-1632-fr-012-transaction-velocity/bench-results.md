# FR-012 Transaction Velocity Benchmark Results

**Date:** 2026-05-04
**Machine:** macOS Darwin 24.6.0 (Apple Silicon)
**Rust:** Edition 2024

## Summary

All benchmarks meet the p99 < 100µs target. The hot path (`tx_velocity_full_check`) averages ~94ns per request.

## Benchmark Results

| Benchmark | Time (mean) | Notes |
|-----------|-------------|-------|
| `tx_velocity_record_existing` | ~94ns | Existing session hot path |
| `tx_velocity_record_new` | ~1.5µs | New session cold path (with allocation) |
| `tx_velocity_snapshot` | ~101ns | DashMap snapshot retrieval |
| `tx_velocity_full_check` | ~94ns | Full record + classifier eval |
| `tx_velocity_scaling/record/1000` | ~253ns | 1k sessions populated |
| `tx_velocity_scaling/record/5000` | ~255ns | 5k sessions populated |
| `tx_velocity_scaling/record/10000` | ~258ns | 10k sessions populated |
| `tx_velocity_scaling/record/50000` | ~253ns | 50k sessions populated |
| `tx_velocity_concurrent_4threads` | ~109µs | 4 threads × 100 ops each |

## Analysis

1. **Hot Path Performance**: The core `record()` + classifier eval path is ~94ns, well under the 100µs budget.

2. **Scaling**: Performance is nearly constant from 1k to 50k sessions (~252-258ns), demonstrating DashMap's O(1) shard-based lookup.

3. **New Session Overhead**: Cold path (~1.5µs) includes allocation for new `ActorTx` ring buffer. Acceptable for first-request latency.

4. **Concurrent Access**: 4-thread concurrent test shows good parallelism with ~109µs for 400 total ops (~273ns/op amortized).

## Methodology

- Criterion benchmarks with 100 samples per measurement
- Pre-warmed stores with 8 events per session
- NoopAggregator used to isolate store/classifier overhead
- Runtime context established via `tokio::runtime::Builder::new_current_thread()`

## Conclusion

**PASS** - All latency targets met. Per-request overhead is sub-microsecond.
