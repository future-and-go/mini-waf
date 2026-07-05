---
phase: 1
title: "Remove dead RiskKeyBuilder + its tests"
status: pending
effort: "20m"
---

# Phase 1: Remove dead RiskKeyBuilder + its tests

## Overview

`RiskKeyBuilder` has zero production callers. Production constructs `RiskKey` via
`RiskKey::from_ip(...)` + direct field assignment (`scorer.rs:264-265`). The only
references are the struct/impls and two dedicated tests, all in
`crates/waf-engine/src/risk/store/store_trait.rs`.

## Context

- Definition: `store_trait.rs:75-116` — `struct RiskKeyBuilder`, `impl RiskKeyBuilder`
  (`new`, `with_ip`, `with_fp_hash`, `with_session`, `build`), `impl Default`.
- Dedicated tests (same file): `key_builder_with_each_axis` (:194-208),
  `key_builder_default_is_empty` (:210-214).
- Coverage preserved elsewhere: `key.rs:161-172` `axis_count_combinations` asserts
  `axis_count()` for 0/1/2/3 axes; `key.rs:150,157` assert single-axis + empty.
  `RiskKey::is_empty()` is exercised by `store_trait.rs:191` (`RiskKey::default()`).

## Implementation Steps

1. Delete the `RiskKeyBuilder` struct, its `impl RiskKeyBuilder`, and `impl Default for
   RiskKeyBuilder` (`store_trait.rs:75-116`), plus the `/// Builder for RiskKey ...` doc
   line above it.
2. Delete the two dedicated tests `key_builder_with_each_axis` and
   `key_builder_default_is_empty`.
3. Remove now-orphaned imports in the test module (e.g. `SessionId` if only the builder
   test used it — check `use crate::risk::key::SessionId;` inside `key_builder_with_each_axis`;
   it is a local `use`, so it disappears with the test). Verify `IpAddr`/`Ipv4Addr` are still
   used by remaining tests (`trait_methods_callable_through_dyn` uses `from_ip`).
4. Confirm no non-test reference survives: `grep -rn "RiskKeyBuilder" crates/` → zero hits.

## Files

- Modify (owner): `crates/waf-engine/src/risk/store/store_trait.rs`

## Success Criteria

- [ ] `grep -rn "RiskKeyBuilder" crates/` returns nothing.
- [ ] `cargo test -p waf-engine store_trait` (and full `-p waf-engine`) green.
- [ ] `cargo clippy -p waf-engine --all-targets` clean (no unused-import warnings).

## Risks & Rollback

- Risk: `axis_count()` multi-axis coverage assumed to live only in the builder test.
  Mitigated — verified `key.rs:161-172` covers 0/1/2/3 axes. If that were wrong, add a
  direct `RiskKey` field-assignment assertion instead of restoring the builder.
- Rollback: revert the single-file diff; nothing else depends on it.
