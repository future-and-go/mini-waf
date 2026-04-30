# Phase 07 — Tests, Benchmarks & Coverage Gate

## Context Links
- Design: brainstorm §8 (success criteria), §7 (perf table)

## Overview
**Priority:** P0 · **Status:** pending · **Effort:** 0.75 d

Verification phase. Stand up integration + e2e + Criterion bench. Hit ≥ 90 % coverage on `crates/waf-engine/src/access/**`. Validate every AC end-to-end against a live Pingora session.

## Key Insights
- AC numbering from `plan.md` table is the test naming source — one test per AC keeps traceability trivial.
- Bench guards regression: phase-02's adapter is the most likely thing to silently slow down.
- E2E tests reuse the synthetic backend from FR-001 phase-06 (path: `crates/gateway/tests/synthetic-backend.rs` or similar — verify exact name during impl).

## Requirements

### Functional — Test Matrix

| AC | Test name | Layer | File |
|---|---|---|---|
| AC-01 | `t_blacklist_v4_returns_403` | e2e | `crates/gateway/tests/access_e2e_blacklist_v4.rs` |
| AC-02 | `t_blacklist_v6_returns_403` | e2e | `crates/gateway/tests/access_e2e_blacklist_v6.rs` |
| AC-03 | `t_longest_prefix_wins` | unit | `crates/waf-engine/src/access/ip_table.rs` |
| AC-04 | `t_empty_lists_disabled` | unit + e2e | unit in `evaluator.rs`, e2e in `access_e2e_disabled.rs` |
| AC-05 | `t_host_gate_strict_per_tier` | e2e | `crates/gateway/tests/access_e2e_host_gate.rs` |
| AC-06 | `t_tier_mode_full_bypass_skips_rules` | e2e | `crates/gateway/tests/access_e2e_tier_mode.rs` |
| AC-07 | `t_reload_bad_yaml_keeps_prior` | integ | `crates/waf-engine/tests/access_reload_bad_yaml.rs` |
| AC-08 | `t_reload_under_load_no_drops` | integ | `crates/waf-engine/tests/access_reload_under_load.rs` |

Plus internal-coverage tests (existing in phase-02..04 already; aggregate count target: ≥ 30 unit tests across `access/**`).

### Non-functional
- `cargo bench -p waf-engine access_lookup` reports p99 ≤ 2 µs at 10 000 entries.
- `cargo llvm-cov --workspace --lcov --output-path target/lcov.info` filtered to `crates/waf-engine/src/access/**` → **≥ 90 %** line coverage.
- All tests deterministic — no flaky timing assertions; reload tests poll up to 2 s with 50 ms intervals.

## Architecture (test layout)

```
crates/waf-engine/
├── benches/
│   └── access_lookup.rs            (Criterion — 1, 100, 10 000 entries; v4 + v6)
└── tests/
    ├── access_reload_bad_yaml.rs
    └── access_reload_under_load.rs

crates/gateway/tests/
├── access_e2e_blacklist_v4.rs
├── access_e2e_blacklist_v6.rs
├── access_e2e_host_gate.rs
├── access_e2e_tier_mode.rs
├── access_e2e_disabled.rs
└── helpers/
    └── access_fixtures.rs            (build a temp YAML + Proxy::with_access_lists)
```

## Related Code Files

### Create
- `crates/waf-engine/benches/access_lookup.rs`
- `crates/waf-engine/tests/access_reload_bad_yaml.rs`
- `crates/waf-engine/tests/access_reload_under_load.rs`
- `crates/gateway/tests/access_e2e_*.rs` (5 files per matrix)
- `crates/gateway/tests/helpers/access_fixtures.rs`

### Modify
- `crates/waf-engine/Cargo.toml` — `[[bench]] name = "access_lookup" harness = false` + `criterion` already in dev-deps (verify)
- Add `--features access_test_helpers` only if test fixtures need to expose internal types — prefer keeping helpers in `tests/helpers/`.

## Implementation Steps

1. **Bench** (`benches/access_lookup.rs`):
   ```rust
   use criterion::{black_box, criterion_group, criterion_main, Criterion};
   use waf_engine::access::IpCidrTable;

   fn bench_v4(c: &mut Criterion) {
       for n in [1usize, 100, 10_000] {
           let mut t = IpCidrTable::new();
           for i in 0..n { t.insert_str(&format!("10.{}.{}.0/24", i / 256, i % 256)).unwrap(); }
           let needle: std::net::IpAddr = "10.5.6.7".parse().unwrap();
           c.bench_function(&format!("v4_lookup_{n}"), |b| b.iter(|| black_box(t.contains(needle))));
       }
   }
   criterion_group!(benches, bench_v4);
   criterion_main!(benches);
   ```
   Add v6 group similarly.
2. **E2E helper** (`helpers/access_fixtures.rs`):
   - `fn temp_yaml(content: &str) -> tempfile::NamedTempFile`
   - `fn proxy_with_access(path: &Path) -> Proxy` builds a `Proxy` with `with_access_lists` + a synthetic backend.
3. **e2e blacklist test pattern**:
   ```rust
   #[tokio::test]
   async fn t_blacklist_v4_returns_403() {
       let yaml = "version: 1\nip_blacklist:\n  - 203.0.113.0/24\n";
       let file = helpers::temp_yaml(yaml);
       let proxy = helpers::proxy_with_access(file.path());
       let resp = proxy.send_test_request("GET", "/", &[("X-Forwarded-For", "203.0.113.5")]).await;
       assert_eq!(resp.status(), 403);
       // assert audit log line
       assert!(test_log_capture::contains("access_decision=block"));
       assert!(test_log_capture::contains("access_reason=ip_blacklist"));
   }
   ```
   *(Use the existing test_log_capture / tracing-subscriber-test pattern from FR-002 e2e tests.)*
4. **`t_reload_under_load_no_drops`**:
   - Spawn 50 concurrent clients each issuing 200 sequential requests for 5 s.
   - Mid-test, modify the YAML file (add a new blacklist entry).
   - Assert: zero connection errors, zero unexpected 5xx, post-reload requests from the new blacklisted IP get 403, prior IPs continue to behave per their state at request time.
5. **Coverage measurement**:
   ```bash
   cargo llvm-cov --workspace --lcov --output-path target/lcov.info \
       --ignore-filename-regex 'tests/|benches/'
   ```
   Then a tiny shell helper:
   ```bash
   ./scripts/coverage-gate.sh crates/waf-engine/src/access 90
   ```
   (script may already exist per FR-002 — check `scripts/`; if not, write a 30-line one.)
6. **CI hook**: add a `make test-fr008` (or extend existing `make test`) that runs the bench in `--quick` mode and fails on coverage drift. Wire after merge.

## Todo List
- [ ] Implement Criterion bench (v4 + v6, 1/100/10k)
- [ ] Helper `access_fixtures` + `temp_yaml` + `proxy_with_access`
- [ ] 5 e2e tests (one per AC-01,02,04,05,06)
- [ ] 2 integration reload tests (AC-07, AC-08)
- [ ] Audit-log-line assertion helper (or reuse FR-002's)
- [ ] `cargo bench --bench access_lookup` runs locally; record p99 in PR description
- [ ] `cargo llvm-cov` showing ≥ 90 % on `access/**`
- [ ] Coverage-gate script (or reuse) + CI hook
- [ ] All tests deterministic (no `sleep` longer than necessary; use polling helpers)

## Success Criteria
- Every test in the matrix passes on `cargo test --workspace --all-features`.
- `cargo bench` p99 ≤ 2 µs at 10 000 v4 entries (v6 ≤ 4 µs acceptable).
- `cargo llvm-cov` reports ≥ 90 % line coverage on `access/**`.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.
- Zero flakes over 10 consecutive runs of reload tests.

## Common Pitfalls
- **Flaky reload timing**: never assert "after sleep(N) the swap happened". Poll `ArcSwap.load()` for the new value with a 2-second timeout and 50 ms tick.
- **Bench measuring noise**: pin to a single CPU (`taskset` on Linux) when comparing across runs; otherwise use `Criterion::with_measurement_time` ≥ 5 s.
- **Coverage skew from bench-only code**: Criterion `bench_function` closures aren't covered by `cargo test`. Don't put production logic inside bench files.
- **Test pollution via global tracing subscriber**: each test must install its own subscriber (`tracing_subscriber::fmt::Layer::with_test_writer`) or use `#[tracing_test::traced_test]`.
- **`tempfile` lifetime**: keep the `NamedTempFile` alive until end of test; dropping it deletes the file mid-reload.

## Risk Assessment
- Medium. Test infra is the most labour-intensive part of this plan. Mitigated by reusing FR-002 helpers wherever possible.

## Security Considerations
- Tests use synthetic IPs (`203.0.113.x` TEST-NET-3, `2001:db8::/32` documentation prefix) — no risk of accidentally blocklisting real production hosts during dev.

## Next Steps
- Phase 08: docs + sample YAML.
