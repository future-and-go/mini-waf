# Fix Report — main-harness CI failures (run 28746923084)

**Date:** 2026-07-06 | **Branch:** main-harness | **Confidence:** high (all claims empirically verified)

## Symptom

CI Test job failed: 3 of 1485 waf-engine lib tests red.

1. `engine::tests::rule_match_risk_deltas_raise_cumulative_score` — `assertion left == right: 90 vs 80`
2. `engine::tests::fp_axis_risk_enforces_across_ips` — expected `Challenge`, got `Block`
3. `risk::store::redis::tests::outage_apply_degrades_and_read_errors` — apply not degraded / read not Err (flaky)

## Root Causes (all test-only; production code correct)

### 1+2. `make_ctx` fixture triggers header-sanity anomaly (+10)

- Fixture (`crates/waf-engine/src/engine.rs` tests) used Chrome-like UA with zero headers.
- `risk/anomaly/header_sanity.rs` fires when UA `looks_like_browser()`: missing `accept` +5, missing `accept-language` +5 → every scored request got +10.
- Tests seed +80 via risk_delta rule; 80+10=90 = default block threshold → score assert fails, Challenge escalates to Block.
- **Why now:** tests landed in #241 whose Test job was SKIPPED (lint gate failed); #245 Test FAILED; failing run is the first complete CI on a HEAD containing them. Never green before.

### 3. 1ns op_timeout raced a real Redis

- Old test set `op_timeout = 1ns` against live REDIS_TEST_URL server assuming timeout always wins.
- `tokio::time::timeout` polls the inner future first; loopback response can arrive first. Instrumented 3 runs: `Err` / `Ok(Some)` / `Ok(None)` — nondeterministic by design. Also a client-side "timed-out" apply still executes server-side, so read could find real state.

## Fix

- `crates/waf-engine/src/engine.rs`: `make_ctx` now sends realistic `accept` + `accept-language` headers with the browser UA → anomaly contributes 0. All other `make_ctx` consumers audited (threshold matrix, canary pin, monitor mode, pipeline-override, fast-path tests) — unaffected.
- `crates/waf-engine/src/risk/store/redis.rs`: rewrote outage test against a local RESP stub (`spawn_silent_after_handshake_stub` + `stub_serve_connection`): answers the redis-rs 0.27 handshake (2× pipelined `CLIENT SETINFO`, `PING`, `INFO cluster` — one `+PONG` per RESP array header), goes permanently silent after the exact frame `$4\r\nINFO` (plain `INFO` substring falsely matches `SETINFO`). Test uses 50ms op_timeout → deterministic timeout on apply/read. No longer needs `REDIS_TEST_URL`.

## Verification (fresh evidence)

- Pre-fix repro reproduced locally byte-for-byte vs CI (scratch postgres via `PG_TEST_URL`).
- Post-fix: 3 target tests pass (`3 passed; 0 failed; 0.60s`).
- Determinism: redis outage test 5/5 consecutive runs, 0.11s each, no Redis running.
- Side-effect sweep: full `cargo test -p waf-engine --lib --all-features` with PG+Redis env → **1484 passed, 1 failed**: `device_fp::config::tests::shipped_yaml_matches_behavior_defaults` — pre-existing, caused by local uncommitted corruption of `configs/device-fp.yaml` (from earlier admin-panel debug session); proven by stash→pass→pop. Unrelated to this fix; CI checks out clean tree.
- `cargo fmt` applied; `cargo clippy -p waf-engine --all-features --lib --tests` clean (fixed `-D clippy::indexing-slicing` + `excessive_nesting` in the stub).
- code-reviewer subagent pass: see session notes.

## Prevention

- New test `engine::tests::header_anomaly_deltas_feed_cumulative_score`: browser UA minus accept/accept-language → asserts `risk_score == 10` — restores explicit integration proof that L2 anomaly deltas feed `inspect()` scoring (coverage the fixture cleanup would otherwise have removed; flagged by code review).
- Fixture comment in `make_ctx` explains why browser UA must ship browser headers.
- Stub doc comments explain the old race (tiny-timeout-vs-live-server) so it isn't reintroduced.
- Redis outage test now hermetic — runs on every CI run instead of only when REDIS_TEST_URL is set.

## Commit scope

Only `crates/waf-engine/src/engine.rs` + `crates/waf-engine/src/risk/store/redis.rs`. Working tree also carries unrelated `configs/*.yaml` changes (challenge/device-fp/risk corruption evidence from open debug task) — MUST be excluded.

## Unresolved questions

- `configs/device-fp.yaml` + `configs/challenge.yaml` corruption (admin-panel write path) still awaiting user decisions from debug report `debug-260705-2331-ddos-config-schema-mismatch-risk-save-report.md`.
