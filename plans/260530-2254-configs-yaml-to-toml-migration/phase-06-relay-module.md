---
phase: 6
title: "relay module"
status: pending
effort: "0.5d"
priority: P1
dependencies: [3]
---

# Phase 6: relay module

## Overview

Smallest in the loader set. No root key (top-level `enabled:`, `providers:`, `intel:`, `trusted_proxies:`, `risk_weights:`). TOML wants a root table for cleanliness — recommendation: introduce a `[relay]` wrapper to match Phase 3/4/5 convention; otherwise scalars at top of file are fine. Decision: **keep root-level** (no wrapper) to match the existing struct that's deserialised at top level (verify; if there's a wrapper struct, add `[relay]`).

## Requirements

- Functional: `RelayConfig::from_path` reads TOML.
- Functional: `configs/relay.toml` ships.
- Functional: `relay_api.rs` switches to TOML codec.

## Related Code Files

- Modify: `crates/waf-engine/src/relay/config.rs` (parser + tests)
- Modify: `crates/waf-engine/src/relay/reload.rs` (test fixtures + path)
- Modify: `crates/waf-engine/tests/relay_hot_reload.rs` (fixture rewrite)
- Modify: `crates/waf-api/src/relay_api.rs` (codec, path)
- Create: `configs/relay.toml`
- Delete: `configs/relay.yaml`

## Implementation Steps

1. **Inspect first:** `grep -n "from_yaml\|serde_yaml" crates/waf-engine/src/relay/config.rs` — confirm parser entrypoint name and root struct.
2. **TDD red:** rewrite YAML literals in `relay/config.rs::tests`, `relay/reload.rs::tests`, `tests/relay_hot_reload.rs` to TOML.
3. Add equivalence test.
4. Hand-write `configs/relay.toml`. TOML structure:
   ```toml
   enabled = false

   [providers.asn_classifier]
   enabled = true
   risk_weight = 15

   [providers.tor_exit]
   enabled = true
   risk_weight = 30
   # ... etc

   [intel.asn_feed]
   url = ""
   refresh_secs = 86400

   trusted_proxies = []

   [risk_weights]
   tor = 30
   datacenter = 15
   bad_asn = 25
   ```
   Note: `trusted_proxies = []` must come BEFORE `[risk_weights]` because it's a scalar of the implicit root table.
5. Swap parser.
6. Update `relay_api.rs`.
7. Delete `configs/relay.yaml`.
8. Tests:
   ```bash
   cargo test -p waf-engine relay::
   cargo test -p waf-engine --test relay_hot_reload
   cargo test -p waf-api relay
   ```

## Todo List

- [ ] Tests rewritten (red)
- [ ] Equivalence test added
- [ ] `configs/relay.toml` hand-written
- [ ] Parser swapped
- [ ] `relay_api.rs` codec + path
- [ ] `configs/relay.yaml` deleted
- [ ] All relay tests green
- [ ] Clippy clean

## Success Criteria

- [ ] `cargo test -p waf-engine relay::` + `tests/relay_hot_reload` green
- [ ] Admin endpoints round-trip JSON unchanged

## Risk Assessment

- **Risk:** Root-level scalars vs sub-tables ordering trap. **Mitigation:** Hand-written TOML strictly orders scalars first.
- **Risk:** Existing struct may already use a root-level `RelayConfig` directly (no wrapper); TOML's root table is implicit — verify the deser path doesn't need a `[relay]` wrapper. **Mitigation:** Phase opens with the inspection step above.
