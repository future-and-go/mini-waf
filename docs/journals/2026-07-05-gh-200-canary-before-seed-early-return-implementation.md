# 2026-07-05 — GH-200: canary before seed early-return (implementation)

## What

`Scorer::score` evaluated the L0 seed layer first, and the `SeedVerdict::Score`
arm returned early into `score_with_l2` — skipping the canary honeypot block
entirely for exactly the IPs most likely to probe honeypot paths (Tor exits,
datacenter/bad ASNs). A Tor-exit scanner hitting `/admin-test` accrued a +30
seed delta instead of the documented force_max + ban + 403.

Fix is a pure intra-function reorder in `crates/waf-engine/src/risk/scorer.rs`:

- Seed verdict is evaluated once into a local (`SeedVerdict::None` when the
  layer is absent or disabled).
- `Whitelisted` still returns Allow immediately — before canary, unchanged.
- The canary block now runs unconditionally for every non-whitelisted request.
- A tail `match` folds the seed contributor into `score_with_l2` on the
  `Score` path; `None` passes the caller deltas through as before.

No signature or public API change; ordering comment updated to match.

## How it was verified

- New `seed_scored_ip_still_hits_canary` (risk/tests/canary.rs): Tor-exit IP
  on a canary path → `Block`, score 100, ban-table entry, and pin persists on
  a later normal request. **Verified to fail on the unpatched scorer** (git
  stash of scorer.rs → test fails; pop → passes), so it genuinely guards the
  ordering.
- New `seed_scored_ip_on_normal_path_accrues_seed_delta`: non-canary path
  still accrues the tor_exit delta (30) — guards against the reorder dropping
  the seed contributor.
- `cargo test -p waf-engine --lib risk`: 239 passed (5 failures are the
  pre-established docker-gated `engine::tests` testcontainer set).
- `cargo clippy -p waf-engine --all-targets` clean; `cargo fmt --all --check`
  clean. `whitelist_bypasses_canary` and
  `canary_path_triggers_block_and_score_100` unchanged and green.

## Gotchas

- `ScorerResult.score` is `u8` — compare against `SeedDeltas::default().tor_exit`
  directly, no widening.
- The whitelist return must stay above the canary block; the mirror test pair
  (`whitelist_bypasses_canary` / `seed_scored_ip_still_hits_canary`) now locks
  the ordering in both directions.
