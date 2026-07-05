# Fix Report — main-harness CI round 3 (run 28754722586): risk seed/credit wiring tests + full docker-suite sweep

**Date:** 2026-07-06 | **Branch:** main-harness | **Confidence:** high (all claims empirically verified)
**Predecessors:** round 1 `fix-260706-0013-...` (87ca279/10e8997), round 2 `fix-260706-0350-...` (0ea2e39)

## Symptom

CI Test job failed 2 tests in `crates/waf-engine/tests/risk_seed_challenge_engine_wiring.rs` — the next never-executed binary behind the fail-fast wall:

1. `tor_exit_ip_accrues_seed_delta_through_inspect` — `score 30 must stay below thresholds` (line 46)
2. `challenge_credit_token_verifies_through_inspect` — `left: 5, right: 30` on the replay assertion (line 95)

## Root Causes (all test-only; production semantics correct and locked by unit tests)

1. **Wrong threshold assumption + fixture blocked as Bot.** The test expected score 30 to stay "allowed" citing "challenge=70". Actual `threshold::decide` challenges at `score >= allow` (default allow=30 — `RiskThresholds` default in `waf-common/src/tier.rs`; pinned by `threshold::tests::score_at_allow_returns_challenge`), so tor_delta 30 lands exactly on the challenge boundary. Additionally the shared `tests/common::make_ctx` fixture sends zero headers — the L1 bot check blocks it (`Reason: Bot`), and risk escalation only fires on plain Allow, so the decision under test was the bot verdict, not the risk one.
2. **Clamp-at-persist assumption.** The test expected replay to score 30. `RiskState.raw_score` is deliberately a pre-clamp accumulator ("can exceed 0..100 range for audit visibility", `state.rs:79`; negative→0 clamp pinned by `reclamp_bounds_score`). The valid credit banks raw −25; replay +30 → raw 5 → clamped 5.
3. **Why now:** merged while CI was red; cargo fail-fast meant this binary first executed in run 28754722586 after round 2 unblocked geoip. Never green before.

## Fix (test expectations aligned to locked semantics)

`crates/waf-engine/tests/risk_seed_challenge_engine_wiring.rs` only:

- Added local `browser_ctx` helper (shared fixture + realistic Chrome UA/accept/accept-language, mirroring the lib `make_ctx` fixture from round 1) so requests pass the bot check and the header-sanity anomaly stays silent. Shared `tests/common/mod.rs` untouched — other suites depend on its headerless shape.
- Test 1 now asserts `risk_score == 30` (the actual wiring proof) **and** `WafAction::Challenge` (score at allow boundary), with a comment explaining the boundary.
- Test 2 now expects replay score 5 (raw −25 + 30), with a comment explaining the pre-clamp accumulator.

## Verification (fresh evidence)

- Pre-fix repro: CI failures reproduced byte-for-byte locally by running the compiled test binary as root (`sudo -n <binary>`) — local docker socket denies the user, root reaches it; this unlocked local execution of every docker-gated suite.
- Post-fix: 3/3 consecutive deterministic runs, `2 passed; 0 failed` each.
- `cargo fmt -p waf-engine -- --check` clean; `cargo clippy -p waf-engine --all-features --tests` clean.
- **Fail-fast wall fully cleared:** cross-referencing the CI run log against the workspace test-binary list showed CI has NEVER executed any of the 57 docker-gated integration suites on recent main-harness (it ran 81 binaries and stopped at this one). All remaining suites were executed locally under sudo-docker:
  - **55 suites / 327 tests — all passed** (15 waf-storage, 10 waf-engine, 30 waf-api), run as compiled binaries under `sudo -n env REDIS_TEST_URL=...` in 4 parallel resumable batches. Plus this file's suite 3/3 deterministic and `config_yaml_regression` 7/7 on a clean tree (round 2). **The fail-fast wall is fully cleared: no more never-executed failures remain anywhere in the workspace.**

## Prevention

- `browser_ctx` doc comment explains both traps (bot check on headerless fixtures; header-sanity anomaly on browser UA without browser headers) — third occurrence of this bug class, now documented at the point of use.
- Comments pin the two production semantics (challenge-at-allow-boundary, pre-clamp raw accumulator) so expectations aren't "corrected" back.

## Commit scope

`crates/waf-engine/tests/risk_seed_challenge_engine_wiring.rs`, this report, journal entry. `configs/*.yaml` corruption evidence (open debug task) — **MUST be excluded**.

## Unresolved questions

- Coverage workflow is chronically red on main-harness, pre-existing and separate from the CI workflow this /fix targets: (a) `Coverage (waf-engine)`: `burst_interval::tests::fires_on_six_samples_at_thirty_ms` is timing-flaky under llvm-cov instrumentation; (b) `Coverage (prx-waf)`: line coverage 4.00% < 5% floor. Both need their own decisions (deflake the timing test; raise prx-waf coverage or adjust floor).
- `configs/challenge.yaml` / `device-fp.yaml` / `risk.yaml` corruption still awaits user decisions from `debug-260705-2331-ddos-config-schema-mismatch-risk-save-report.md`.
