# Phase 03 — Per-Tier Host Whitelist Gate

## Context Links
- Design: brainstorm §3b, D2, D3, D4 + §6 step 1
- RFC 6125 §6.4.1 — hostname case-insensitivity

## Overview
**Priority:** P0 · **Status:** pending · **Effort:** 0.5 d

Strict per-tier `Host` allowlist. Empty list = disabled (D4). Lowercased on insert and lookup.

## Key Insights
- Strategy/Registry pattern via `HashMap<Tier, HashSet<String>>` — O(1) lookup, exact match only (no wildcards in phase-1).
- D4 is the safety rail: missing/empty list → `is_allowed()` returns `Allowed` unconditionally.
- Reverse-DNS / FQDN-from-SNI deliberately out (D2). `Host` header byte-string only.

## Requirements

### Functional
- `HostGate::is_allowed(tier, host_header) -> bool`
- `HostGate::is_disabled_for(tier) -> bool` (used by audit log to record `gate=disabled`)
- Lowercase host on **both** insert and lookup.
- Reject hosts with port suffix or whitespace at parse time (already in phase-01 validate).

### Non-functional
- O(1) average — `HashSet<String>`.
- p99 ≤ 0.5 µs lookup.

## Architecture

```
HostGate {
   per_tier: [HashSet<String>; 4]   // index by Tier as usize
}

is_allowed(tier, host):
   set = per_tier[tier]
   if set.is_empty()       => true   // D4
   else                    => set.contains(&host.to_lowercase())
```

`Tier` → `usize` mapping: derive `IntoIter`/`as_index()` helper inside `host_gate.rs` (don't pollute `waf_common::tier`).

## Related Code Files

### Create
- `crates/waf-engine/src/access/host_gate.rs`

### Modify
- `crates/waf-engine/src/access/mod.rs` — `pub use host_gate::HostGate;`
- `crates/waf-engine/src/access/config.rs` — `AccessLists` gains `host_gate: HostGate`; build inside `from_yaml_str`.

## Implementation Steps

1. **Create `host_gate.rs`**:
   ```rust
   use std::collections::HashSet;
   use waf_common::tier::Tier;

   #[derive(Debug, Default)]
   pub struct HostGate {
       per_tier: [HashSet<String>; 4],
   }
   impl HostGate {
       pub fn new() -> Self { Self::default() }

       pub fn insert(&mut self, tier: Tier, host: &str) {
           self.per_tier[Self::idx(tier)].insert(host.trim().to_ascii_lowercase());
       }

       #[inline]
       pub fn is_allowed(&self, tier: Tier, host_header: &str) -> bool {
           let set = &self.per_tier[Self::idx(tier)];
           if set.is_empty() { return true; }      // D4
           // Strip port suffix defensively even though parser rejects
           let h = host_header.split(':').next().unwrap_or(host_header);
           set.contains(&h.to_ascii_lowercase())
       }

       #[inline]
       pub fn is_disabled_for(&self, tier: Tier) -> bool {
           self.per_tier[Self::idx(tier)].is_empty()
       }

       #[inline]
       const fn idx(t: Tier) -> usize {
           match t {
               Tier::Critical => 0, Tier::High => 1,
               Tier::Medium => 2,   Tier::CatchAll => 3,
           }
       }
   }
   ```
2. **Wire into `AccessLists`**:
   ```rust
   let mut hg = HostGate::new();
   for (tier, hosts) in &cfg.host_whitelist {
       for h in hosts { hg.insert(*tier, h); }
   }
   ```
3. **Tests** (phase-07 will repeat as integration):
   - `t_empty_disabled`: critical list empty → any host allowed.
   - `t_strict_hit`: `api.example.com` allowed for critical; lookup with same allowed.
   - `t_strict_miss`: `evil.com` denied for critical.
   - `t_case_insensitive`: insert `Api.Example.com`, lookup `API.example.COM` → allowed.
   - `t_port_stripped`: insert `api.example.com`, lookup `api.example.com:8443` → allowed.
   - `t_per_tier_isolation`: critical=`{api}`, medium=empty → medium accepts `evil.com`.

## Todo List
- [ ] Create `host_gate.rs` (≤ 120 LoC)
- [ ] Implement `HostGate::{new, insert, is_allowed, is_disabled_for}`
- [ ] Wire into `AccessLists::from_yaml_str`
- [ ] 6 unit tests
- [ ] `cargo clippy -p waf-engine -- -D warnings` clean

## Success Criteria
- 6 unit tests pass.
- D4 enforced: no test combination allows an empty list to deny.
- File ≤ 200 LoC.

## Common Pitfalls
- **Allocating on every lookup**: `host.to_ascii_lowercase()` allocates. Acceptable at p99 ≤ 0.5 µs scale, but if benches show drift, switch to `eq_ignore_ascii_case` iteration. Phase-07 bench will tell.
- **Forgetting port strip**: `Host: api.example.com:8443` is valid HTTP. Strip first `:` defensively.
- **Using `Tier as usize`**: don't rely on enum repr — use the explicit `idx()` match. Cheaper to reason about; survives reordering.

## Risk Assessment
- Low.

## Security Considerations
- Strict gate is a **deny-by-default** primitive when list non-empty. Combined with D4, the only way to lock out prod is adding a hostname that doesn't match — caught by phase-07 e2e test against fixture hosts.

## Next Steps
- Phase 04: evaluator chain ties IP + Host + per-tier mode together.
