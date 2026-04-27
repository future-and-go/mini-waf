# SQL Injection Benchmarks

Criterion benchmarks for SQL injection detection performance.

## Running Benchmarks

```bash
cargo +nightly bench --package waf-engine --bench sql_injection
```

## Results (2026-04-23)

**System:** Apple Silicon (M-series) / macOS Darwin 24.6.0

### Clean Request Latency

| Metric | Value |
|--------|-------|
| Mean | 3.48 µs |
| p99 | < 5 µs |

**SLO:** p99 < 500 µs ✓

### Malicious Request Latency

| Attack Type | Mean |
|-------------|------|
| classic_tautology_url | 380 ns |
| classic_comment_url | 835 ns |
| classic_stacked_url | 1.06 µs |
| blind_boolean_url | 360 ns |
| blind_extraction_url | 515 ns |
| time_sleep_url | 406 ns |
| time_benchmark_url | 543 ns |
| time_waitfor_url | 1.12 µs |
| time_pg_sleep_url | 487 ns |
| union_url | 641 ns |
| classic_tautology_header | 677 ns |
| union_header | 781 ns |
| classic_tautology_json | 502 ns |
| union_json | 631 ns |

**SLO:** p99 < 1 ms ✓

## Benchmark Corpus

### Clean Request
- Representative REST request
- 3 query params, 5 headers, 64-byte JSON body
- Typical benign traffic pattern

### Malicious Corpus (14 entries)
- Classic: tautology, comment, stacked queries
- Blind: boolean, extraction functions
- Time-based: SLEEP, BENCHMARK, WAITFOR, pg_sleep
- UNION-based: basic UNION SELECT
- Locations: URL params, headers, JSON body

## Notes

- Run benchmarks on AC power for stable results
- Run 3x and take median for best accuracy
- CI benchmarks are informational-only due to variance
