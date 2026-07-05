# main-harness CI round 3: risk wiring tests wrong about locked semantics; fail-fast wall finally cleared

**Date:** 2026-07-06 04:45 +07:00
**Severity:** Medium (CI red on main-harness, third consecutive red run, each revealing the next hidden layer)
**Component:** waf-engine (risk seed/challenge-credit integration tests)
**Status:** COMPLETE (fix verified locally, awaiting commit)

## What Happened

Round 2 unblocked the geoip binary; CI then reached `tests/risk_seed_challenge_engine_wiring.rs` for the first time and failed both its tests. Both encoded wrong assumptions about production semantics that are locked by unit tests elsewhere:

1. Expected score 30 to stay allowed ("challenge=70") — but `threshold::decide` challenges at `score >= allow` (default allow=30), so the default tor_delta lands exactly on the boundary. Worse, the decision under assert wasn't even a risk decision: the shared fixture sends zero headers, the L1 bot check blocks that as `Bot`, and risk escalation only fires on plain Allow.
2. Expected replay to score 30 — but `raw_score` is deliberately a pre-clamp accumulator, so the −25 valid credit banks and replay lands at raw 5.

Fixed the test file only: a local `browser_ctx` helper (fixture + realistic browser headers) and corrected expectations with comments pinning both semantics.

## The Brutal Truth

1. **Third rake in the same garden.** Rounds 1–3 are all the same failure class: tests merged while CI was red, never executed, wrong about the system. This time I refused to push until NOTHING unexecuted remained.
2. **`sudo -n <binary>` was the unlock.** 57 integration suites need docker; the local socket denies the user. Running the compiled test binaries directly as root reproduced CI byte-for-byte and made the whole hidden set locally verifiable — no cargo, no 10-minute-timeout pain, resumable result files.
3. **Cross-referencing CI logs vs the binary list proved the blind spot was total:** CI had executed 81 binaries and *none* of the 57 docker-gated ones. Every "green" CI Test job to date said nothing about half the integration surface.
4. **Fixture realism strikes again.** Round 1: browser UA without browser headers → +10 anomaly. Round 3: no headers at all → bot-blocked before risk even runs. Minimal fixtures keep asserting against the wrong subsystem.

## Evidence

- Fixed suite: 3/3 consecutive `2 passed; 0 failed` runs under sudo-docker.
- Full docker-gated sweep: **55 suites / 327 tests, all passed** (15 waf-storage, 10 waf-engine, 30 waf-api).
- fmt + clippy clean.

## Lessons

- When a test's failure message cites a threshold, read the decision function before trusting the comment — `decide()` uses `allow` and `block`; the `challenge` field is decorative.
- An integration fixture must be realistic enough to reach the layer under test; otherwise the assert silently rebinds to an earlier layer's verdict.
- After fixing the visible CI failure, enumerate what CI has *never run* (run log vs binary list) — fail-fast makes "green so far" a much weaker statement than it looks.

Report: `plans/reports/fix-260706-0433-ci-risk-seed-wiring-tests-and-docker-suite-sweep-report.md`
