---
phase: 1
title: "Keep-old-on-failure reload guard"
status: completed
dependencies: []
effort: "1.5h"
---

# Phase 1: Keep-old-on-failure reload guard

## Overview

`GeoIpService::reload` (`crates/waf-engine/src/geoip.rs:72-87`) unconditionally
stores the newly loaded searchers and returns `Ok(any_loaded)`. If an xdb file is
missing or corrupt at reload time, `load_searcher` returns `None`
(`geoip.rs:131-146`) and a **working** searcher is silently replaced with `None`,
disabling geo lookups. This phase makes the swap per-family and preserves the old
searcher when the new load fails, surfacing the failure via `Err`. Independent of
GH-197 — touches only `geoip.rs`.

## Requirements

- Functional: on reload, a family whose new load fails but whose current searcher
  is present keeps the old searcher (no swap to `None`).
- Functional: a family whose new load succeeds is atomically swapped as today.
- Functional: a family that was `None` and stays `None` (first-time / degraded)
  is unchanged — no error for that alone.
- Functional: when any working searcher was preserved instead of replaced,
  `reload` returns `Err` naming the affected family/families so the caller logs it.
- Non-functional: readers still see only old-or-new via `ArcSwapOption`
  (no torn state); no reader downtime.

## Architecture

Rework `reload` (`geoip.rs:72-87`) to decide per family. Sketch:

```rust
pub fn reload(&self) -> anyhow::Result<bool> {
    let mut swapped = false;          // at least one family got a new searcher
    let mut preserved: Vec<&str> = Vec::new();  // families kept old on failure

    for (slot, path, label) in [
        (&self.ipv4, self.ipv4_path.as_str(), "IPv4"),
        (&self.ipv6, self.ipv6_path.as_str(), "IPv6"),
    ] {
        match load_searcher(path, self.cache_policy, label) {
            Some(new) => { slot.store(Some(new)); swapped = true; }
            None => {
                if slot.load().is_some() {
                    // keep the working searcher; do NOT store None
                    preserved.push(label);
                } // else already None → leave as-is
            }
        }
    }

    if !preserved.is_empty() {
        return Err(anyhow::anyhow!(
            "GeoIP reload: new load failed for {}; kept previous searcher(s)",
            preserved.join(", ")
        ));
    }
    if swapped { info!("GeoIP: hot-reloaded xdb files from disk"); }
    Ok(swapped)
}
```

Notes:
- Keep the `[ipv4, ipv6]` iteration to avoid duplicating the load/decide block
  (DRY); `slot` is `&ArcSwapOption<Searcher>`.
- `slot.load().is_some()` reads the *current* (old) searcher to decide preserve
  vs leave-None. This is the load-then-conditional-store that fixes the swap.
- `Ok(false)` now means "nothing new loaded and nothing needed preserving"
  (i.e. both families already `None`) — same degraded meaning as before.
- Do NOT change `init`, `lookup`, `is_available`, or `load_searcher` signatures.

## Related Code Files

- Modify: `crates/waf-engine/src/geoip.rs` — `reload` body (lines 72-87); add
  reload unit tests in the existing `#[cfg(test)] mod tests` (line 194+).
- Reference (do not change): `load_searcher` (`geoip.rs:131-146`),
  `geoip_updater.rs:157` (only production caller; already handles `Err` via
  `warn!` at `geoip_updater.rs:158-160`).

## Implementation Steps

1. Replace the `reload` body with the per-family preserve-on-failure logic above.
2. Update the doc comment (`geoip.rs:64-71`) to state the keep-old-on-failure
   guarantee and the new `Err`-on-preserved return.
3. Add unit tests (see Success Criteria). Building a real `Searcher` needs an xdb
   fixture — if the repo has no committed xdb, test at the observable seam:
   construct a service pointing at a **present** temp file, `init`, assert
   `is_available()`; then delete/rename the file, `reload()`, assert it returns
   `Err` **and** `is_available()` is still `true` (old searcher preserved). Locate
   any existing xdb test fixture first (`rg -l xdb crates/waf-engine`); reuse it.
   If no `Searcher`-constructible fixture exists, fall back to asserting the
   preserve-vs-store decision via a small refactor seam or document the gap and
   cover it in the Phase 3 acceptance layer.
4. `cargo test -p waf-engine geoip`; `cargo clippy -p waf-engine`.

## Success Criteria

- [ ] Reload with the xdb file removed after a successful `init` returns `Err`
      and `is_available()` remains `true` (old searcher still serves).
- [ ] Reload after replacing the file with a valid xdb swaps in the new searcher
      and returns `Ok(true)`.
- [ ] Reload when both families were already `None` (never loaded) returns
      `Ok(false)` and no `Err`.
- [ ] `geoip_updater.rs` still compiles and surfaces the new `Err` via its
      existing `warn!` (no caller change required).

## Risk Assessment

- **No committed xdb fixture (Med).** Real `Searcher` construction needs an xdb
  file. Likelihood the CI repo lacks one is real. Mitigation: search for an
  existing fixture first; if absent, cover the observable guarantee
  (`is_available()` stays true across a failed reload) using whatever xdb the
  geoip tests already use, or defer the fullest assertion to Phase 3 acceptance.
- **Return-type semantics change (Low).** `reload` now returns `Err` in a case
  that previously returned `Ok`. Only one production caller, which already treats
  `Err` as a warn (`geoip_updater.rs:158-160`); no silent behavior change.
- **Rollback:** revert `geoip.rs` `reload` to the unconditional-store version;
  no schema, no persisted state, no cross-file impact.
</content>
