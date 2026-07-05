# main-harness CI: 3 Test Failures Fixed (fixture anomaly skew + redis timeout race)

**Date:** 2026-07-06 00:25 +07:00
**Severity:** Medium (CI red on main-harness)
**Component:** waf-engine (engine tests, redis risk store test)
**Status:** COMPLETE (fix verified, awaiting commit approval)

## What Happened

CI run 28746923084 failed 3 of 1485 waf-engine lib tests. All three were test-only defects; production code correct. None was ever green: #241's Test job was skipped (lint gate), #245's Test failed — the red run was the first complete CI on a HEAD containing them.

1. `rule_match_risk_deltas_raise_cumulative_score` + `fp_axis_risk_enforces_across_ips`: shared `make_ctx` fixture used a Chrome UA with zero headers → header-sanity anomaly (+5 missing accept, +5 missing accept-language) silently added +10 to every scored request; 80+10=90 hit the block threshold (score assert failed; Challenge became Block). Fixed the fixture to send realistic browser headers.
2. `outage_apply_degrades_and_read_errors`: 1ns op_timeout raced a live Redis — tokio polls the inner future before the timer, so loopback replies could win (observed Err / Ok(Some) / Ok(None) across 3 instrumented runs). Rewrote against a hermetic RESP stub that answers the redis-rs handshake then goes silent, so a 50ms timeout fires deterministically; test no longer needs REDIS_TEST_URL.

## The Brutal Truth

1. **My first stub version hung.** Silence trigger matched substring `INFO`, which also matches `SETINFO` in the handshake pipeline — stub went silent before PING, `RedisRiskStore::new` (whose PING/INFO are not timeout-wrapped) hung forever, and the 5x verification loop sat 8+ minutes before I caught it. Fix: match the exact RESP frame `$4\r\nINFO`.
2. **Clippy caught two more revisions**: `-D clippy::indexing-slicing` (panic-free `get(..n)` slicing) and `excessive_nesting` (extracted `stub_serve_connection`).
3. **Code review flagged real lost coverage**: the accidental +10 was the only engine-level proof that L2 anomaly deltas reach `inspect()` scoring. Added `header_anomaly_deltas_feed_cumulative_score` (UA minus accept headers → risk_score == 10) to restore it explicitly.
4. Local sweep showed 1 unrelated failure: `shipped_yaml_matches_behavior_defaults` fails only against the locally corrupted `configs/device-fp.yaml` (open admin-panel write-path bug, separate debug report). Proven via stash → pass → pop.

## Evidence

- 4 target tests: `4 passed; 0 failed` (scratch postgres via PG_TEST_URL).
- Redis outage test: 5/5 consecutive deterministic passes, 0.11s each, no Redis running.
- Full sweep: 1484/1485 (single failure = local yaml corruption, above).
- `cargo fmt --check` clean; clippy clean; code-reviewer: DONE, no blocking findings.

## Lessons

- A tiny timeout vs a live server is a race, not a guarantee — `tokio::time::timeout` polls the inner future first, and a client-side timeout doesn't undo the server-side write.
- Fixtures that trip heuristic detectors (browser UA without browser headers) poison every downstream expectation; keep fixtures realistic per the detector's own definition of clean.
- When merging PRs whose Test job was skipped or already red, the breakage surfaces later on someone else's run.

Report: `plans/reports/fix-260706-0013-ci-engine-risk-tests-and-redis-outage-flake-report.md`
