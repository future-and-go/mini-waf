---
phase: 4
title: "Tests Unit + E2E"
status: pending
priority: P1
effort: "1d"
dependencies: [3]
---

# Phase 4: Tests Unit + E2E

## Overview

Comprehensive test coverage: unit (per module), integration (full check pipeline), E2E (live HTTP), bench (latency).

## Requirements

**Coverage targets:**
- Unit: each classifier ≥3 tests; recorder ≥4; role_tagger ≥3
- Integration: full request → signal flow with mock aggregator
- E2E: HTTP request synthesis triggers signal observable via `/api/admin` audit log or aggregator probe
- Bench: per-request overhead p99 <100µs

## Architecture

Mirror existing test layout (FR-011 reference: `crates/waf-engine/tests/behavioral_anomaly.rs` if exists; else `tests/` integration crate).

## Related Code Files

**Create:**
- `crates/waf-engine/src/checks/tx_velocity/recorder.rs` — `#[cfg(test)] mod tests` (already partial in P1; expand)
- `crates/waf-engine/src/checks/tx_velocity/classifiers/*.rs` — per-classifier tests
- `crates/waf-engine/tests/tx_velocity_integration.rs` — full pipeline
- `tests/e2e/tx-velocity.sh` OR `tests/e2e/tx_velocity_e2e.rs` — match existing E2E convention
- `crates/waf-engine/benches/tx_velocity_bench.rs` (criterion)

**Modify:**
- `crates/waf-engine/Cargo.toml` — add `criterion` dev-dep + `[[bench]]` entry if not already

## Implementation Steps

### Unit tests
1. **Role tagger** — known paths map correctly; unknown returns `None`; regex patterns hot-reload
2. **Recorder** — append; ring overflow drops oldest; janitor purges idle entries; cooldown suppresses spam
3. **SequenceTimingClassifier** — Login→OTP <1500ms fires; ≥1500ms doesn't; OTP without prior Login no-op
4. **WithdrawalVelocityClassifier** — 3+ withdrawals/60s fires; 2 doesn't; events outside window ignored
5. **LimitChangeBurstClassifier** — analogous

### Integration tests
6. **Full pipeline mock** — construct `TxVelocityCheck` with mock aggregator collector; feed synthetic `RequestCtx` sequence; assert aggregator received expected signals

### E2E
7. **Live HTTP** — start WAF + dummy backend; curl Login→OTP→Deposit fast; verify signal in audit log (JSON)
8. **Hot-reload E2E** — edit YAML, wait 1s, re-test, confirm new threshold applied

### Bench
9. **Criterion bench** — measure `Check::check()` latency on hot path with populated DashMap (10k sessions, 1k req/s); assert p99 <100µs

### Anti-cheat
- No fake data, no test-specific code paths in production (Iron Rule)
- All thresholds come from config, not hardcoded test fixtures inside check logic

## Todo List

- [ ] Unit tests: role_tagger (3+)
- [ ] Unit tests: recorder (4+)
- [ ] Unit tests: each classifier (3+ each = 9 total)
- [ ] Unit tests: cooldown logic
- [ ] Integration test: full pipeline with mock aggregator
- [ ] E2E test: live HTTP triggers signal
- [ ] E2E test: hot-reload picks up config change
- [ ] Criterion bench: per-request latency
- [ ] All tests pass: `cargo test -p waf-engine`
- [ ] Bench p99 <100µs documented in test report

## Success Criteria

- [ ] `cargo test -p waf-engine` 100% green (no flakes on 3 reruns)
- [ ] Coverage ≥80% on `tx_velocity` module (verify via tarpaulin or grcov)
- [ ] E2E test runnable in CI (`scripts/test-e2e.sh` or equivalent)
- [ ] Bench output saved to `plans/260504-1632-fr-012-transaction-velocity/bench-results.md`
- [ ] No flakiness from time-based assertions (use injected clock OR generous tolerances)

## Risk Assessment

| Risk | Mitigation |
|---|---|
| Time-based test flakiness | Inject `Clock` trait OR use deterministic `now_ms` fixture |
| E2E test fragile to backend startup race | Existing harness already handles; reuse `test-e2e-guideline.md` |
| Bench env-dependent | Run on dev machine; document spec in bench-results.md |

## Security Considerations

- Tests must NOT use real session cookies / production data
- E2E test backend isolated (existing harness pattern)
