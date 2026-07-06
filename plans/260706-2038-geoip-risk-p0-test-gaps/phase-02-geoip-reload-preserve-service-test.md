---
phase: 2
title: "GeoIP Reload Preserve Service Test"
status: completed
priority: P1
dependencies: []
---

# Phase 2: GeoIP Reload Preserve Service Test

<!-- Updated: Validation Session 1 - small committed binary fixture fallback user-approved -->

## Overview

Service-level test proving `GeoIpService::reload()` preserves the working
searcher when the on-disk xdb file has gone bad: reload returns `Err` naming
the failing family, `is_available()` stays true, and lookups keep answering
from the old in-memory searcher. Today only the pure helper
`family_reload` (geoip.rs:159) is unit-tested; the service path is not.

## Requirements

- Functional: load valid xdb → overwrite file with garbage → `reload()` →
  `Err` mentioning the family (e.g. "IPv4") → `is_available() == true` and
  `lookup()` still returns data without panic.
- Non-functional: no production code change expected (`geoip.rs:77` reload
  already documents keep-on-failure semantics); test-only phase plus possibly
  one committed fixture.

## Architecture — the fixture problem

There is **no valid `.xdb` fixture in the repo**, and
`minimal_xdb_bytes()` in `crates/waf-engine/tests/geoip_updater_schedule.rs:144`
is documented as *failing* ip2region validation (that test relies on
rejection). This phase needs a file that `ip2region::Searcher::new` accepts.

Resolution order:

1. Read the vendored `ip2region` crate source (`cargo doc`/registry checkout;
   version pinned in `crates/waf-engine/Cargo.toml`) to see exactly what
   `Searcher::new` validates at load time (header magic/version, index
   pointers, file length).
2. Preferred: extend `minimal_xdb_bytes()` into a `valid_xdb_bytes()` test
   helper — 256-byte v2 header with correct version + index-pointer fields and
   a zero/one-segment vector index sized so validation passes. Keep the helper
   next to the new test in `tests/geoip_lookup.rs` (share via a small
   `tests/common` module only if both files need it).
3. Fallback: generate a tiny real xdb once with the upstream ip2region maker
   tool and commit it under `crates/waf-engine/tests/fixtures/` (keep it a few
   KB). Document provenance in a sibling comment.

## Related Code Files

- Modify: `crates/waf-engine/tests/geoip_lookup.rs`
- Possibly create: `crates/waf-engine/tests/fixtures/<tiny>.xdb` (fallback only)

## Implementation Steps

1. Determine `Searcher::new` load-time validation (step 1 above); pick helper
   vs fixture.
2. Test body (tempdir, mirroring `init_with_corrupt_xdb_falls_back_gracefully`
   at geoip_lookup.rs:126):
   1. Write valid xdb bytes to `<tmp>/v4.xdb`; init service with that path and
      a nonexistent v6 path; assert `is_available()`.
   2. Capture a baseline `lookup()` result for a fixed IPv4 address.
   3. Overwrite `<tmp>/v4.xdb` with garbage bytes.
   4. `reload()` → assert `Err`, and the error string names the IPv4 family.
   5. Assert `is_available()` still true; `lookup()` of the same IP still
      returns the baseline (old searcher intact, no panic).
3. Suggested name: `reload_failure_keeps_serving_previous_searcher`.
4. Run `cargo test -p waf-engine --test geoip_lookup`.

## Success Criteria

- [x] New service-level test passes and fails if reload semantics regress
      (verified by temporarily simulating a swap-to-None — reverted, geoip.rs
      has no diff). Test: `reload_failure_keeps_serving_previous_searcher`.
- [x] No committed fixture: `searchable_xdb_bytes()` helper handcrafts a
      fully searchable v3 xdb in memory (Searcher::new only validates the
      256-byte header: index_policy ∈ {1,2}, ip_version ∈ {4,6}). Baseline
      lookup returns real region data under FullMemory cache.

## Risk Assessment

- Main risk: ip2region validates deeply enough that no handcrafted file loads.
  Mitigation: fallback fixture (step 3). If the maker tool is impractical,
  stop and report — do not weaken the assertion to "reload returns Err on
  never-loaded service" (that is already covered by unit tests).
