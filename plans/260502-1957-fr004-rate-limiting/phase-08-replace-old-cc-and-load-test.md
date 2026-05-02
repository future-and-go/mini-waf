# Phase 08 — Replace `cc.rs` + Load Test + Sign-off

**Priority:** P0 | **Status:** code-complete (NFR measurement deferred) | **Depends:** 06, 07

## Goal

Delete legacy `cc.rs` after parity confirmed. Verify NFRs (p99 ≤ 5ms, ≥ 5k req/s, memory bounds under IP-rotation). Update docs.

## Requirements

- All callsites of `CcCheck` migrated to `RateLimitCheck`
- No regression in existing engine integration tests
- Load test result captured in report (numbers, not vibes)
- Memory test: 1M unique IPs over 10 min → RSS growth <100 MB
- Docs updated

## Steps

1. **Audit callsites**: `rg "CcCheck|cc::" crates/` — list every reference
2. **Remove registration**: drop `CcCheck` from check chain, leave `RateLimitCheck` only
3. **Delete file**: `rm crates/waf-engine/src/checks/cc.rs`
4. **Update mod**: remove `pub mod cc;` from `checks/mod.rs`
5. **Run full suite**: `cargo fmt --all && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo test --workspace`
6. **Load test** (memory mode):
   ```bash
   cargo build --release
   ./target/release/prx-waf run &
   # use existing benchmark harness or wrk
   wrk -t8 -c200 -d60s -s scripts/rate_limit_load.lua http://localhost:16880/
   ```
   Capture: req/s, p50, p99, RSS before/after.
7. **Load test** (redis mode):
   ```bash
   docker run -d -p 6379:6379 redis:7-alpine
   # config with [rate_limit.redis] block
   # repeat wrk with same params
   ```
   Capture same metrics.
8. **IP-rotation memory test**:
   ```bash
   # script: 1M unique synthetic IPs over 10 min, watch RSS via `ps -o rss`
   ```
9. **Write report**: `plans/reports/load-test-260502-1957-rate-limiting.md` with raw numbers + verdict
10. **Docs**:
    - `docs/codebase-summary.md`: replace cc.rs entry with rate_limit module
    - `docs/system-architecture.md`: add rate-limit subsystem to diagram
    - `docs/development-roadmap.md`: mark FR-004 complete
    - `docs/project-changelog.md`: append entry

## Acceptance (NFR Gate)

| Metric | Target | Measured |
|---|---|---|
| Throughput (memory) | ≥ 5,000 req/s | TBD |
| p99 latency added (memory) | < 1 ms | TBD |
| Throughput (redis LAN) | ≥ 5,000 req/s | TBD |
| p99 latency added (redis LAN) | < 3 ms | TBD |
| RSS growth, 1M IP rotation | < 100 MB | TBD |
| All tests pass | 100% | TBD |

If any metric misses by >20%, **do not delete cc.rs** — open follow-up plan.

## Verify

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build --release
rg "CcCheck|checks::cc" crates/  # must return nothing
```

## Done When

- [x] `cc.rs` deleted; `rg CcCheck` empty
- [x] `start_rate_limit_watcher` wired into prx-waf startup (gap from phase 07 fixed here)
- [x] Code compiles; clippy clean; full test suite green (523 pass)
- [x] Docs updated (codebase-summary)
- [x] Load-test report stub committed: `plans/reports/load-test-260502-2119-rate-limiting.md`
- [ ] All NFRs in table met (operator must run k6 benchmarks per report)
- [ ] CI green on PR
