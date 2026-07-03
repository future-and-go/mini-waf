---
phase: 5
title: "Verification and benches"
status: completed
priority: P2
dependencies: [1, 2, 3, 4]
---

# Phase 5: Verification and benches

<!-- Updated: Validation Session 1 - Valkey test env confirmed (Redis-gated tests now required); bench list corrected; #199 criteria added -->

## Overview

Cross-cutting verification gate after phases 1–4 land: full test suite, lint/format gates, bench regression check, and a final sweep of the acceptance criteria from issue #206 plus the #199 criteria folded into Phase 2.

## Requirements

- Functional: all four acceptance criteria from issue #206 verifiably hold.
- Non-functional: no regressions in existing benches (`crates/waf-engine/benches/`).

## Implementation Steps

1. `cargo test -p waf-engine` — full engine suite.
2. `cargo test --workspace` if engine-adjacent crates (waf-common, gateway) reference touched APIs; skip if no cross-crate surface changed.
3. `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --check` (CI enforces both — see recent commits a5f8042/1dc5f30).
4. **Required:** `REDIS_TEST_URL=redis://127.0.0.1:6379 cargo test -p waf-engine redis` against the local **Valkey** instance (protocol/Lua-compatible with the `redis` crate; confirmed available in Validation Session 1). This is the executable proof for Phase 2, including the #199 divergent-score conformance test. If Valkey is unexpectedly down, fix the environment rather than skipping — do not ship Phase 2 on inspection alone.
5. Bench spot-check: run the closest existing benches — `tx_velocity_bench`, `risk_anomaly`, `rule_eval`, `access_lookup` — before/after on the same machine; numbers are indicative only — the primary evidence is structural (O(1) ops, single RTT, skipped work), asserted by tests and code inspection.
6. Walk the acceptance criteria checklist in `plan.md` (four from #206 + two from #199) and check each with a pointer to the proving test/inspection.
7. Update issues #206 and #199 Handoff Logs via `gh issue comment` summarizing what was verified; close-worthiness of #199 is decided by the human after review.

## Success Criteria

- [x] `cargo test -p waf-engine` green.
- [x] clippy `-D warnings` + fmt green.
- [x] Redis-gated tests green against Valkey (`REDIS_TEST_URL`), including the #199 conformance test.
- [x] All six acceptance criteria (4× #206, 2× #199) checked off with evidence pointers.

## Risk Assessment

- The Redis store's proof now depends on the Valkey instance being reachable at test time. Valkey is RESP- and Lua-compatible, so no code changes are expected — but if any script behavior diverges (e.g. cjson edge cases), treat it as a finding, not an excuse to skip.
