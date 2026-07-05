---
phase: 5
title: "Acceptance tests + quality gates"
status: completed
priority: P1
dependencies: [1, 2, 3, 4]
---

# Phase 5: Acceptance tests + quality gates

## Overview

End-to-end proof for all four issue acceptance criteria plus workspace-wide
quality gates. Individual phases carry their own unit/conformance tests; this
phase covers the cross-crate integration seams those can't reach.

## Requirements

- Integration test exercising the real wiring: API PUT → file → watcher →
  engine snapshot → scoring behavior change.
- Redis-backed paths covered by the CI redis job added for GH-198
  (`REDIS_TEST_URL`-gated conformance).

## Related Code Files

- Create: `crates/waf-engine/tests/` or extend `tests/engine_lifecycle.rs` —
  follow wherever the GH-195/GH-198 integration tests landed (check first;
  do not invent a new test root if one fits)
- Modify: `crates/waf-api` handler tests for risk endpoints

## Implementation Steps

1. Integration: build engine with tempdir `configs/risk.yaml` (enabled=false),
   `start_risk_watcher`, assert score path inert; write enabled config through
   the API handler (not raw fs) → poll until `risk_cfg` snapshot flips →
   assert scoring active (nonzero score / header emission path).
2. Backend integration: risk.yaml with `store.backend: redis` +
   `REDIS_TEST_URL` → scored actor state visible in redis (key-prefix scan);
   test skips cleanly when the env var is unset (matches conformance gating).
3. API tests: PUT round-trip AC test (Phase 3), clear/credit tests (Phase 4)
   all green in one run.
4. Gates: `cargo test --workspace`, `cargo clippy --workspace --all-targets`,
   `cargo fmt --check`.
5. Update docs only if operator-visible behavior is documented elsewhere
   (grep `docs/` for risk.yaml references; the store backend + hot-reload
   behavior likely needs one line where ddos/tx-velocity watchers are described).

## Success Criteria

- [ ] All four GH-196 acceptance criteria have a named test proving them.
- [ ] Full workspace test + clippy + fmt clean.
- [ ] Redis-gated tests pass locally against a redis container and skip without it.

## Risk Assessment

- Watcher-based integration tests are timing-sensitive — use the poll-until-
  deadline shape from `reload.rs` tests (2s deadline, 20ms interval), never
  fixed sleeps.
