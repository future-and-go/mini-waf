---
phase: 6
title: "Regression Tests"
status: pending
priority: P1
effort: "1h"
dependencies: [2, 3, 4, 5]
---

# Phase 6: Regression Tests

## Overview

Add regression tests that load every `configs/*.yaml` file through its engine parser. These tests run in CI and prevent future schema divergence — if someone edits a YAML file in a way the engine can't parse, CI catches it immediately.

## Requirements

- Functional: One test per config file that loads it through the engine's typed parser
- Functional: Tests run in CI (`cargo test`)
- Non-functional: Tests are fast (no I/O beyond file read, no network)

## Related Code Files

- Create: `crates/waf-engine/tests/config_loader.rs` (or add to existing test file if one exists)
- Read: all `configs/*.yaml` files
- Read: each config module's `from_path()` or `from_yaml_str()` method

## Implementation Steps

1. Check if `crates/waf-common/tests/config_loader.rs` already exists (it was listed in the file tree earlier). If so, extend it. Otherwise create a new integration test.

2. Write one test per config:
   ```rust
   #[test]
   fn configs_challenge_yaml_loads() {
       let path = Path::new(env!("CARGO_MANIFEST_DIR"))
           .join("../../configs/challenge.yaml");
       ChallengeFileConfig::from_path(&path)
           .expect("configs/challenge.yaml must parse");
   }
   ```

3. Cover all 8 configs:
   - `challenge.yaml` → `ChallengeFileConfig::from_path()`
   - `ddos.yaml` → `DdosFileConfig::from_path()`
   - `device-fp.yaml` → `DeviceFpFileConfig::from_path()` (or equivalent)
   - `rate-limit.yaml` → `RateLimitFileConfig::from_path()` (or equivalent)
   - `relay.yaml` → `RelayConfig::from_yaml_path()`
   - `risk.yaml` → `RiskFileConfig::from_path()` (or equivalent)
   - `tier-policies.yaml` → skip (no engine loader; admin API only)
   - `tx-velocity.yaml` → `TxVelocityFileConfig::from_path()` (or equivalent)

4. Run `cargo test -p waf-engine -- config` and verify all pass

5. Verify CI includes these tests (they should be picked up automatically by `cargo test`)

## Success Criteria

- [ ] Integration test exists for each config file with an engine loader (7 of 8)
- [ ] All tests pass locally
- [ ] Tests would catch the exact bugs found in this audit (ddos, relay schema mismatch)
- [ ] `cargo check -p waf-engine` passes

## Risk Assessment

- **Path sensitivity**: Tests use relative paths from `CARGO_MANIFEST_DIR`. Works in workspace builds but verify CI runs from the workspace root.
- **tier-policies.yaml**: No engine loader exists — skip this file in the regression suite. It's covered by the admin API tests.
