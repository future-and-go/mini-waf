---
phase: 2
title: "Acceptance test + quality gates"
status: pending
priority: P2
dependencies: [1]
effort: 30m
---

# Phase 2: Acceptance test + quality gates

## Overview

Add the regression test the issue requires: a seed-classified IP (Tor exit)
hitting a canary path must be blocked with `force_max` + a `DynamicBanTable`
entry — the exact scenario the early-return bug let slip through. Add it as the
mirror of the existing `whitelist_bypasses_canary` test so both ordering
directions are locked.

## Requirements

- New `#[tokio::test]` in `crates/waf-engine/src/risk/tests/canary.rs` (module
  already registered: `risk/mod.rs:36` → `mod tests;`, `risk/tests/mod.rs` →
  `mod canary;`).
- Asserts, for a Tor-exit IP on a canary path: `WafAction::Block { .. }`,
  `score == 100`, `ban_table.contains(ip, now_ms)`, and store state pinned
  (`force_max` reached — read back via `scorer.store()` and `is_pinned(now_ms)`).
- Add a companion assertion (same or second test) that a seed-Score IP on a
  **non-canary** path still accrues its seed delta through `score_with_l2`
  (guards against Phase 1 dropping the contributor).

## Related Code Files

- Modify: `crates/waf-engine/src/risk/tests/canary.rs` — add test(s) using the
  existing helpers/imports in that file.

## Test construction (grounded in existing file)

Mirror `whitelist_bypasses_canary` (`risk/tests/canary.rs:269-322`) but seed the
IP as a Tor exit instead of whitelisting it. `make_ctx` in that file uses
`client_ip = 192.168.1.100`; either reuse it as the Tor-exit IP or pick a
distinct IP and set it in a local ctx — key point: the seed table must classify
`ctx.client_ip` as `SeedVerdict::Score`.

Wiring pattern (same imports already present at `canary.rs:10-27`):

```rust
#[tokio::test]
async fn seed_scored_ip_still_hits_canary() {
    let store = Arc::new(MemoryRiskStore::new());
    let ban_table = Arc::new(DynamicBanTable::new());

    let cfg = RiskConfig {
        enabled: true,
        canary: CanaryConfig {
            enabled: true,
            paths: vec!["/admin-test".to_string()],
            ban_ttl_secs: 3600,
        },
        ..Default::default() // seed.enabled defaults true (config.rs:181,422)
    };
    let swap = Arc::new(ArcSwap::from(Arc::new(cfg)));

    // Seed table classifies the client IP as a Tor exit → SeedVerdict::Score.
    let ctx = make_ctx("/admin-test");
    let mut builder = SeedTablesBuilder::new();
    builder.add_tor_exit(ctx.client_ip);
    let tables = Arc::new(ArcSwapSeed::from(Arc::new(builder.build())));
    let seed = Arc::new(SeedLayer::new(tables, SeedDeltas::default()));

    let canary = Arc::new(CanaryLayer::with_ban_table(
        vec!["/admin-test".to_string()],
        Arc::clone(&ban_table),
        3600,
    ));

    let mut scorer = Scorer::new(store, swap);
    scorer.set_seed(seed);
    scorer.set_canary(canary);

    let now_ms = 1_000_000;
    let result = scorer.score(&ctx, None, &[], None, now_ms).await.unwrap();

    // Canary must fire despite the seed Score classification.
    assert!(matches!(result.action, WafAction::Block { .. }));
    assert_eq!(result.score, 100);
    assert!(ban_table.contains(ctx.client_ip, now_ms));
}
```

Notes for the implementer:
- `SeedTablesBuilder::build()` returns an owned `SeedTables`; the
  `whitelist_bypasses_canary` test wraps it as `Arc::new(builder.build())` inside
  `ArcSwapSeed::from` — reuse that exact form (do not call `.into_arc()` here, to
  match the sibling test).
- To also assert `force_max` reached the store, read back via the test-only
  accessor `scorer.store()` (`scorer.rs:126`, `#[cfg(test)]`) and check the
  built `RiskKey` state `is_pinned(now_ms)` (`state.rs:137`). If reconstructing
  the key is noisy, the `score == 100` + ban-table assertions already prove the
  canary path ran; treat the pin read-back as optional strengthening.
- Optional second test / assertion: same wiring but `make_ctx("/normal-path")`
  → expect non-Block and a non-zero score reflecting the Tor delta (30), proving
  the seed contributor survives the reorder on the non-canary path.

## Implementation Steps

1. Add the test(s) above to `risk/tests/canary.rs`.
2. `cargo test -p waf-engine risk` — new test passes, existing
   `whitelist_bypasses_canary` and `canary_path_triggers_block_and_score_100`
   still pass.
3. `cargo clippy -p waf-engine --all-targets` clean.

## Success Criteria

- [ ] New test fails on unpatched `scorer.rs` (early return) and passes after
      Phase 1 — confirms it actually guards the bug.
- [ ] `Block` + `score == 100` + ban-table entry asserted for the Tor-exit +
      canary-path case.
- [ ] Non-canary seed-Score path asserted to still accrue the seed delta.
- [ ] `cargo test -p waf-engine risk` and `cargo clippy -p waf-engine --all-targets` green.

## Risk Assessment

- **Test not actually reproducing the bug:** if the seed table doesn't classify
  `ctx.client_ip`, the test would pass even on unpatched code. Mitigation: the
  success criterion explicitly requires verifying the test fails pre-Phase-1
  (run it against HEAD before applying the fix, or reason from the control flow).

## Rollback

Test-only additions; revert the test file. No production code affected in this
phase.
