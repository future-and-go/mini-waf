---
phase: 4
title: "Velocity and geo alloc removal"
status: completed
priority: P2
dependencies: []
---

# Phase 4: Velocity and geo alloc removal

## Overview

Two independent micro-fixes, grouped because each is a handful of lines:

- **Velocity (finding 4)**: `VelocityStore::record` (`crates/waf-engine/src/risk/velocity/window.rs:126`) does `windows.entry(key.clone())` — cloning `RiskKey` (which can own a session `Vec<u8>`) on **every** request, even when the window already exists (the steady state).
- **Geo (finding 5)**: `GeoIpService::lookup` (`crates/waf-engine/src/geoip.rs:107`) allocates `ip.to_string()` per request although the vendored ip2region `Searcher::search` accepts `Ipv4Addr`/`Ipv6Addr` directly (`IpValueExt` impls exist for both). And `GeoCheck::geo_matches` (`crates/waf-engine/src/checks/geo.rs:133`) re-allocates `geo.iso_code.to_uppercase()` **per rule per request**; normalization belongs at rule-load time (`load_rules`, geo.rs:64) plus once per lookup.

The geo lookup itself stays — `ctx.geo` is consumed for log enrichment (engine.rs:980/1031/1128) even when no geo rules exist.

## Requirements

- Functional: identical velocity counts and geo match results, including case-insensitive ISO/country matching regardless of rule input case.
- Non-functional: steady-state `record()` performs zero clones; geo hot path performs zero avoidable `String` allocations (`ip.to_string()`, per-rule `to_uppercase()` gone).

## Architecture

**Velocity** — read-then-insert on the DashMap:

```rust
pub fn record(&self, key: &RiskKey, now_ms: i64) -> Option<u32> {
    let now_sec = (now_ms / 1000) as u64;
    let count = if let Some(window) = self.windows.get(key) {
        window.record(now_sec)          // SlidingWindow::record is &self (atomics)
    } else {
        self.windows.entry(key.clone()).or_default().record(now_sec)
    };
    if count > self.threshold { Some(count) } else { None }
}
```

`SlidingWindow::record` uses atomics (`&self`), so a shared `get()` ref suffices. The get-then-entry race is benign: two first-requests for a key may both take the miss branch; `entry` serializes them and at most one bucket increment lands on a discarded default — the same class of approximation the sliding window already accepts. Note: `get` on hit vs `entry` differs in lock type (read vs write shard lock), which also reduces shard contention.

**GeoIP** — dispatch by family instead of stringifying:

```rust
let raw = match ip {
    IpAddr::V4(v4) => searcher.search(v4),
    IpAddr::V6(v6) => searcher.search(v6),
};
```

(The `warn!` on error still formats the ip — that path is cold.) In `parse_region`/`normalize`, leave the owned `String` fields alone — `GeoIpInfo` is a `waf-common` public type consumed by log enrichment; changing field types is out of scope. The `"0"` sentinel already maps to `String::new()` (no alloc).

**Geo rules** — normalize once at load: in `GeoCheck::load_rules` (geo.rs:64), uppercase every entry of `rule.iso_codes` before storing (the doc on the field says "uppercase" but nothing enforces it — API-created rules may be lowercase). Additionally uppercase `iso_code` once in `parse_region` (ip2region emits uppercase ISO codes; `make_ascii_uppercase` in place is free of alloc). Then `geo_matches` becomes a plain `contains(&geo.iso_code)` — zero per-rule allocs. `countries` matching already uses `eq_ignore_ascii_case` (alloc-free) — leave it.

## Related Code Files

- Modify: `crates/waf-engine/src/risk/velocity/window.rs` — `record()` (122-128).
- Modify: `crates/waf-engine/src/geoip.rs` — `lookup()` (94-116), `parse_region` (149-168, iso_code uppercase-in-place).
- Modify: `crates/waf-engine/src/checks/geo.rs` — `load_rules` (64-66, normalize iso_codes), `geo_matches` (131-141, drop `to_uppercase()`).

## Implementation Steps

1. Velocity: rewrite `record` per above; add a test that a pre-existing key's second `record` returns 2 (behavioral, clone-freeness is by inspection).
2. GeoIP: family-dispatch `search`; keep error handling identical.
3. Geo rules: uppercase `iso_codes` in `load_rules`; uppercase `iso_code` in `parse_region` via `make_ascii_uppercase`; simplify `geo_matches` line 133 to `rule.iso_codes.contains(&geo.iso_code)`.
4. Add/extend a geo test: rule loaded with lowercase `["cn"]` still blocks a request whose xdb lookup yields `cn`/`CN` — proving load-time + lookup-time normalization compose.
5. Run existing geo + velocity test modules.

## Success Criteria

- [x] Steady-state `record()` takes the `get()` branch — no `RiskKey` clone on hit.
- [x] No `ip.to_string()` in `GeoIpService::lookup` success path.
- [x] No `to_uppercase()` in `geo_matches`; case-insensitivity proven by test with lowercase rule input.
- [x] Existing velocity/geo tests pass unchanged (or updated only for the new normalization guarantee).

## Risk Assessment

- Velocity get/entry race is benign (documented above); it does not lose settled counts on hot keys, only potentially one increment at first-touch under contention.
- ISO normalization tightening could *change* behavior only for rules that previously silently failed to match lowercase codes — that is a bug-fix direction, aligned with #197's broader geo findings.
