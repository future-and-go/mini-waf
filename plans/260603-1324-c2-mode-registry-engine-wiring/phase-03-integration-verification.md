---
phase: 3
title: "Integration Verification"
status: pending
priority: P0
effort: "1h"
dependencies: [2]
---

# Phase 3: Integration Verification

## Overview

End-to-end verification that `set_profile` API calls propagate through ModeRegistry → engine → WafDecision → X-WAF-Mode header. Uses the existing interop control integration test infrastructure in `crates/waf-api/tests/`.

## Requirements

- Functional: `set_profile(features=[X], mode=log_only)` → engine inspect produces `decision.mode == LogOnly` for feature X while other features stay Enforce.
- Non-functional: Tests run in <5s, no external dependencies.

## Related Code Files

- Create: `crates/waf-api/tests/interop_mode_enforcement.rs` — integration tests
- Read: `crates/waf-api/tests/interop_control_integration.rs` — existing test patterns to follow
- Read: `crates/gateway/src/waf_observability_headers.rs` — verify X-WAF-Mode derivation path

## Implementation Steps

### Wire Test Helper

1. Read `crates/waf-api/tests/common/mod.rs` — identify `start_test_server()` or equivalent helper that constructs AppState + engine.

2. Update the test helper to call `engine.set_mode_registry(state.mode_registry.clone())` so API and engine share the same ModeRegistry. Without this, `set_profile()` writes to AppState's registry but engine uses its own (empty) one.

### Write Integration Tests

3. Create `crates/waf-api/tests/interop_mode_enforcement.rs`

4. Test `set_profile_all_log_only_affects_engine` — call `set_profile(scope=all, mode=log_only)`, invoke engine.inspect on a request that triggers a detection. Assert `decision.mode == LogOnly`.

3. Test `set_profile_feature_log_only_selective` — call `set_profile(scope=features, features=[injection_control], mode=log_only)`. Trigger SQLi detection → assert LogOnly. Trigger bot detection → assert Enforce (unaffected feature).

4. Test `set_profile_policy_log_only_granular` — call `set_profile(scope=policies, feature=injection_control, policies=[sqli], mode=log_only)`. Trigger SQLi → LogOnly. Trigger XSS → Enforce (same feature, different policy).

5. Test `reset_state_clears_mode_overrides` — set feature to log_only, call `reset_state`, verify engine reverts to Enforce for that feature.

6. Test `set_profile_enforce_overrides_previous_log_only` — set feature to log_only, then set it back to enforce. Verify engine uses Enforce.

7. Test `capabilities_snapshot_reflects_mode` — after `set_profile`, call `capabilities` and verify `active` snapshot shows the correct mode per feature.

### Verify Gateway Path (Read-Only)

8. Verify `WafDecisionMeta::from_decision()` copies `decision.mode` correctly — this is existing code, just confirm with a read pass that the `mode` field flows through.

9. Verify `waf_observability_headers.rs` reads `meta.mode` for X-WAF-Mode — existing code, confirm no changes needed.

### Final Verification

10. Run `cargo test --workspace` — all tests pass
11. Run `cargo clippy --workspace` — zero warnings
12. Run `cargo fmt --all -- --check` — no formatting drift
13. Grep for remaining `log_only_mode` in engine.rs — should only appear in field access for `apply_mode`, not standalone if-checks

## Success Criteria

- [ ] set_profile(scope=all) → engine decisions reflect mode change
- [ ] set_profile(scope=features) → only targeted features change mode
- [ ] set_profile(scope=policies) → only targeted policies within a feature change mode
- [ ] reset_state → mode overrides cleared, engine reverts to defaults
- [ ] capabilities snapshot reflects current mode per feature
- [ ] Gateway X-WAF-Mode path confirmed (read-only — no changes needed)
- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace` zero warnings
- [ ] Zero standalone `host_config.log_only_mode` checks remain in engine.rs

## Risk Assessment

- **Low risk:** Integration tests build on existing interop test infrastructure.
- **Edge case:** Test setup must wire ModeRegistry into both AppState and engine (same clone). If test helper creates them separately, overrides won't propagate.
  - **Mitigation:** Update test helper to call `engine.set_mode_registry(state.mode_registry.clone())` — same pattern as main.rs.
