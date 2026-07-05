---
phase: 1
title: "Reorder canary check before seed-Score early return"
status: completed
priority: P2
dependencies: []
effort: 30m
---

# Phase 1: Reorder canary check before seed-Score early return

## Overview

Restructure `Scorer::score` so the FR-028 canary honeypot block runs for every
non-whitelisted request, including IPs the seed layer scores. Today the
`SeedVerdict::Score` arm returns early before the canary block, so Tor/datacenter
IPs skip the honeypot trap entirely.

## Requirements

- Functional: after the fix, ordering is whitelist → canary → seed-Score + L2.
  A seed-Score IP on a canary path is blocked (force_max + ban) instead of
  continuing to `score_with_l2` with only a seed delta.
- Behavior-preserving: whitelisted IPs still short-circuit to Allow *before*
  canary; non-seed (`None`) IPs behave exactly as today; the seed contributor
  still reaches `score_with_l2` unchanged for the non-canary Score path.
- No public API / signature change.

## Related Code Files

- Modify: `crates/waf-engine/src/risk/scorer.rs` — the `score()` body only
  (current seed block `156-178`, canary block `180-206`, tail call `208-209`).

## Current control flow (verified HEAD 9ee484b)

`scorer.rs:156-209`:

1. Seed block (`157-178`): `match seed.evaluate(ctx.client_ip)`
   - `Whitelisted` → return Allow (`161-167`).
   - `Score { delta, kind }` → build seed contributor, `return score_with_l2(...)` (`168-175`). **← early return skips canary.**
   - `None` → fall through (`176`).
2. Canary block (`180-206`): `check_and_ban` → `force_max` → return `Block`.
3. Tail (`208-209`): `score_with_l2(ctx, fp_key, sync_deltas, ...)`.

## Target control flow

1. Evaluate the seed verdict once into a local (guarded by `self.seed` +
   `cfg.seed.enabled`, defaulting to `SeedVerdict::None` when the layer is absent
   or disabled).
2. `Whitelisted` → return Allow (unchanged, still before canary).
3. Canary block runs unconditionally for the non-whitelisted case (moved above
   the seed-Score handling).
4. `Score { delta, kind }` → build seed contributor, prepend to `sync_deltas`,
   call `score_with_l2` with the combined deltas.
5. `None` → call `score_with_l2` with `sync_deltas` as today.

## Implementation Steps

1. Replace the `if let Some(ref seed) ... match { ... }` block (`157-178`) with a
   single verdict computation, e.g.:

   ```rust
   // L0 seed layer — evaluate once; whitelist short-circuits everything.
   let seed_verdict = match (&self.seed, cfg.seed.enabled) {
       (Some(seed), true) => seed.evaluate(ctx.client_ip),
       _ => SeedVerdict::None,
   };

   if matches!(seed_verdict, SeedVerdict::Whitelisted) {
       return Ok(ScorerResult { action: WafAction::Allow, score: 0, is_new: false });
   }
   ```

2. Leave the canary block (`180-206`) exactly where it is — it now sits after the
   whitelist return but before any seed-Score handling. Update the comment at
   `scorer.rs:180-181` so it reads that canary runs after whitelist and before
   seed scoring / other layers (state the invariant; no plan or FR codes in the
   comment text).

3. Replace the tail call (`208-209`) with a match on the retained verdict so the
   seed-Score contributor is folded in on that path only:

   ```rust
   match seed_verdict {
       SeedVerdict::Score { delta, kind } => {
           let seed_contrib = Contributor::new(ContributorKind::Seed(kind), i16::from(delta), now_ms);
           let mut all_deltas = vec![seed_contrib];
           all_deltas.extend_from_slice(sync_deltas);
           self.score_with_l2(ctx, fp_key, &all_deltas, tx_endpoint, now_ms, &cfg).await
       }
       // Whitelisted handled above; None falls through with caller deltas only.
       _ => self.score_with_l2(ctx, fp_key, sync_deltas, tx_endpoint, now_ms, &cfg).await,
   }
   ```

   (Exact idiom is the implementer's choice — a retained `Option<Contributor>`
   built before the canary block is equally fine. The invariant that matters:
   canary evaluated between whitelist and seed-Score.)

4. `cargo build -p waf-engine` then `cargo test -p waf-engine risk` — existing
   seed + canary tests stay green.

## Success Criteria

- [x] `score()` evaluates the canary block for a non-whitelisted seed-Score IP
      (control-flow verified by reading the reordered function).
- [x] Whitelist still returns Allow before canary; `None` path unchanged.
- [x] Ordering comment matches the code.
- [x] `cargo test -p waf-engine risk` green; no signature changes.

## Risk Assessment

- **Likelihood low / impact medium:** a botched reorder could drop the seed
  contributor on the non-canary path (silent scoring regression). Mitigation:
  Phase 2 keeps/extends a test asserting a seed-Score-only IP (no canary hit)
  still accrues its seed delta via `score_with_l2`.
- **Whitelist regression:** moving code near the whitelist arm could let a
  whitelisted IP reach canary. Mitigation: `whitelist_bypasses_canary`
  (`risk/tests/canary.rs:269`) must stay green — do not move the `Whitelisted`
  return below the canary block.

## Rollback

Single-file, single-function change. Revert `scorer.rs` to restore the prior
early-return ordering; no data, config, or schema migration involved.
