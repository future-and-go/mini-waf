# Phase 04 — Benchmark + Acceptance Tests

## Priority
P0 — gates merge.

## Objective
Prove every acceptance criterion with tests. Prove p99 added latency < 500 µs with Criterion.

## Files to Create
- `crates/waf-engine/benches/sql_injection.rs` — Criterion bench
- `crates/waf-engine/tests/sql_injection_acceptance.rs` — integration test against full `SqlInjectionCheck`

## Files to Modify
- `crates/waf-engine/Cargo.toml` — add `criterion` dev-dep if missing, `[[bench]] name = "sql_injection" harness = false`

## Acceptance Test Matrix (4 × 3 = 12 base cases, each ≥2 variants = ≥24 tests)

| Attack Type | URL param | Header | JSON body |
|---|---|---|---|
| Classic (tautology, comment, stacked) | ✓ | ✓ | ✓ |
| Blind (boolean, extraction, conditional) | ✓ | ✓ | ✓ |
| Time-based (SLEEP, BENCHMARK, WAITFOR, pg_sleep) | ✓ | ✓ | ✓ |
| UNION-based | ✓ | ✓ | ✓ |

Plus negatives: clean requests for each location must NOT trigger.
Plus boundary: JWT tokens in `Authorization` header must not false-positive (`eyJ...==` no SQL keywords).

## Criterion Bench

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};

fn bench_clean(c: &mut Criterion) {
    let checker = SqlInjectionCheck::new();
    let ctx = make_clean_ctx();   // representative clean request
    c.bench_function("sqli_check_clean", |b| b.iter(|| {
        black_box(checker.check(black_box(&ctx)))
    }));
}

fn bench_malicious(c: &mut Criterion) {
    let checker = SqlInjectionCheck::new();
    let mut group = c.benchmark_group("sqli_check_malicious");
    for (name, ctx) in malicious_corpus() {
        group.bench_with_input(BenchmarkId::from_parameter(name), &ctx,
            |b, ctx| b.iter(|| black_box(checker.check(black_box(ctx)))));
    }
}

criterion_group!(benches, bench_clean, bench_malicious);
criterion_main!(benches);
```

Corpus:
- Clean: typical REST request, 3 query params, 5 headers, 1 KB JSON body
- Malicious: one per attack × location (12 entries)

SLO gate: `cargo bench --bench sql_injection` → p99 clean < 500 µs, p99 malicious < 1 ms. Documented in bench README, reviewed manually on dev workstation.

## Todo
- [ ] Write 24+ unit + integration tests per matrix
- [ ] Write clean-request negatives per location
- [ ] Write JWT-in-Authorization non-FP test
- [ ] Write Criterion bench
- [ ] Run `cargo bench --bench sql_injection` on dev workstation, record CPU model + results in `benches/README.md`
- [ ] Run `cargo test --workspace` — all green
- [ ] Run `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] Run `cargo fmt --all -- --check`
- [ ] Delegate final review to `code-reviewer` agent

## Success Criteria
- Every cell in the 4×3 matrix has ≥2 passing tests
- All clean-location negatives pass
- p99 clean-request latency < 500 µs
- Zero regressions in existing test suite
- `code-reviewer` agent returns DONE

## Risks
- Criterion bench on CI may be noisy → informational-only in CI, gate on local dev workstation
- Flaky bench from power-state variance → run 3× on AC power, take median

## Open Questions (carry-forward)
- Per-host `SqliScanConfig` override — track as future work, not v1
- Expose redaction/scan counts as metrics — track as future work
