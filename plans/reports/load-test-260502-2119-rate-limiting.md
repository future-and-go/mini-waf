# FR-004 Rate Limiting — Phase 08 Sign-off Report

**Date:** 2026-05-02
**Branch:** main
**Plan:** `plans/260502-1957-fr004-rate-limiting/phase-08-replace-old-cc-and-load-test.md`
**Mode:** code-only (B1) — load-test execution deferred to operator

## Code Changes

| File | Change |
|---|---|
| `crates/waf-engine/src/checks/cc.rs` | **deleted** (235 lines) |
| `crates/waf-engine/src/checks/mod.rs` | removed `pub mod cc;` + `pub use cc::CcCheck;` |
| `crates/waf-engine/src/engine.rs` | removed `CcCheck` import + registration; updated comment |
| `crates/prx-waf/src/main.rs` | added `engine.start_rate_limit_watcher(rl_path)` after `start_file_watcher()` |
| `docs/codebase-summary.md` | replaced `cc_limiter.rs` entry with `rate_limit/` + updated Phase 5 description |

## Wiring Gap Found & Fixed

`start_rate_limit_watcher()` defined in waf-engine since phase 07 but had **zero callers** — production rate-limit subsystem was inert (default empty config). Fixed in this phase: prx-waf `run_server` startup now reads `config.rate_limit.config_path` and starts the watcher. Default config already points at `configs/rate-limit.yaml`.

## Verify Gates (all pass)

```
cargo fmt --all -- --check     ✓
cargo clippy --workspace --all-targets --all-features -- -D warnings  ✓
cargo test --workspace          ✓ (waf-engine: 525→523, lost 2 deleted CcCheck tests)
rg "CcCheck|checks::cc" crates/ ✓ empty
```

## NFR Acceptance Table — DEFERRED

Operator must run k6 benchmarks (`scripts/k6-benchmark-waf.js` adapted for rate-limit traffic) and fill the table. Plan called for `wrk` + `scripts/rate_limit_load.lua`; neither exists in the repo. Use existing k6 harness instead.

| Metric | Target | Measured |
|---|---|---|
| Throughput (memory) | ≥ 5,000 req/s | TBD |
| p99 latency added (memory) | < 1 ms | TBD |
| Throughput (redis LAN) | ≥ 5,000 req/s | TBD |
| p99 latency added (redis LAN) | < 3 ms | TBD |
| RSS growth, 1M IP rotation | < 100 MB | TBD |

### How to run (operator checklist)

1. Build release: `cargo build --release`
2. Edit `configs/rate-limit.yaml` → set `enabled: true`
3. Memory mode: `./target/release/prx-waf run &` then `k6 run scripts/k6-benchmark-waf.js` (adapt URL/duration)
4. Redis mode: `docker run -d -p 6379:6379 redis:7-alpine`, uncomment `[rate_limit.redis]` block, rebuild with `--features redis-store`, repeat k6
5. IP-rotation memory: synthetic 1M unique `X-Forwarded-For` over 10 min, monitor `ps -o rss <pid>`
6. Append numbers to this report, update Done When checklist below

## Done When

- [x] `cc.rs` deleted; `rg CcCheck` empty
- [x] `start_rate_limit_watcher` wired into prx-waf startup
- [x] Code compiles; clippy clean; full test suite green
- [x] Docs updated (codebase-summary)
- [ ] NFRs measured and recorded (deferred to operator)
- [ ] CI green on PR (after commit/push)

## Unresolved Questions

1. **Plan's referenced files don't exist in repo:** `scripts/rate_limit_load.lua`, `wrk` binary. Plan should be updated to use k6 (already in `scripts/k6-benchmark-waf.js`) or those tools must be added.
2. **`configs/rate-limit.yaml` default has `enabled: false`.** Phase 07 ships the loader/reloader but ships disabled. Should the default be flipped to `enabled: true` with conservative tiers? Currently shipping FR-004 in "off" mode.
3. **`rate_limit_reloader` field is `OnceLock` and `WafEngine.rate_limit_reloader` is held but its drop never runs explicitly** — fine for process-lifetime services, but flagged for awareness if engine ever needs hot-restart semantics.
4. **`docs/system-architecture.md` and `docs/project-roadmap.md`** still reference "CC/DDoS rate limiting" generically — these are accurate enough not to need surgical edits but a future docs-pass should align terminology with FR-004 / rate_limit module naming.
