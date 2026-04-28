# Phase 07 — Performance + Leak Validation + Abort Resilience

## Context Links
- Design doc §5 (#13, #16), §6 risks
- Phases 01–06 (all code in place)
- ACs: AC-21 (p99 ≤ 5ms), AC-24 (client-abort resilience), comprehensive leak sweep across AC-15/17

## Overview
- **Priority:** P1 (final gate)
- **Status:** pending
- **Description:** Run `wrk` benchmark for AC-21, regex leak sweep across responses, client-abort loop for AC-24. Produce a single sign-off report.

## Key Insights
- p99 budget is overhead vs direct-to-backend baseline, not absolute. Bench script must measure both.
- Leak sweep is a **belt-and-suspenders** test on top of unit tests; runs against a corpus of 100 sample responses.
- Abort test must verify no FD/connection leak (count via `/proc/self/fd` on Linux or `lsof` count).

## Requirements
**Functional**
- `wrk -c100 -t4 -d60s` against WAF and against backend directly; latency histograms compared.
- Leak sweep: regex `(?i)pingora|server: pingora|via:|x-powered-by-waf|x-waf|10\.\d+\.|backend\.internal` zero matches across response headers + bodies of 100 random requests.
- Abort: 100 iterations of `curl --max-time 0.05` mid-request → no panics, FD count steady (within ±5).

**Non-Functional**
- Bench script reproducible; outputs JSON for CI artifact.

## Architecture
- `bench/wrk-runner.sh` — orchestrates two `wrk` runs and computes overhead delta.
- `bench/leak-sweep.rs` — drives 100 requests through synthetic backend with crafted internal-ref payloads; greps responses.
- `bench/abort-loop.rs` — spawns N short-lived clients that disconnect mid-upload.

## Related Code Files
**Create**
- `crates/gateway/bench/wrk-runner.sh`
- `crates/gateway/tests/fr001_bench.rs` (Criterion-based; gates p99 overhead)
- `crates/gateway/tests/fr001_leak_sweep.rs`
- `crates/gateway/tests/fr001_abort.rs`

**Modify**
- `crates/gateway/Cargo.toml` — `[dev-dependencies]` add `criterion`

## Implementation Steps
1. Bench harness: spin up synthetic backend + WAF, then run `wrk` against both. Parse latency histograms (`wrk` Lua script output) → assert `(p99_waf - p99_direct) <= 5ms`. Mark test `#[ignore]` for default run; CI runs with `--ignored` on perf job.
2. Leak sweep: send requests to endpoints designed to leak — backend returns headers `Via: backend`, `Server: backend/1.0`, body containing `http://backend.internal/path`, `10.0.0.5`. Capture WAF response → regex assert zero forbidden tokens.
3. Abort loop: 100 iterations spawning a curl-like client (`reqwest` request body that drops mid-stream); record FD count before/after. Assert delta ≤ 5.
4. Combine results into a markdown report at `plans/reports/planner-260428-1011-fr001-validation.md` (NOTE: validation is run-time output; this phase only writes the test code that produces it).

## Todo List
- [ ] Bench harness + p99 assertion
- [ ] Leak sweep test
- [ ] Abort loop test
- [ ] CI perf job (separate from default tests)
- [ ] Final sign-off checklist in plan.md

## Success Criteria
- AC-21: WAF p99 - direct p99 ≤ 5ms at 5k req/s, body 1 KiB.
- AC-24: 100 abort iterations → no panic, no `tracing::error!`, FD count stable.
- Leak sweep zero matches → confirms AC-15/17 robustness.

## Risk Assessment
| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Bench env variance > 5ms budget itself | H | M | Run baseline + WAF on same host, same time, average 3 runs; gate on median delta |
| FD count noisy on macOS | M | L | Use Linux CI runner for abort test; gate macOS as informational |
| `wrk` not installed on CI | M | L | Provide install step; alt: `oha` |

## Security Considerations
- Bench harness must not expose external ports.
- Leak-sweep payloads must not include real secrets.

## Next Steps
- Mark FR-001 closed; produce final validation report linking all 25 ACs to passing test runs.
