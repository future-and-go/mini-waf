# Phase 02 — IP CIDR Table (Patricia Trie Adapter)

## Context Links
- Design: brainstorm §3d (lookup DS), §7 (perf), D9, D11
- Crate docs: https://docs.rs/ip_network_table

## Overview
**Priority:** P0 · **Status:** complete · **Effort:** 0.5 d

Implement `IpCidrTable` — a thin **Adapter** over `ip_network_table::IpNetworkTable<()>`. Native dual-stack v4 + v6, longest-prefix wins.

## Key Insights
- The crate's table already does longest-prefix; we expose only `insert` + `contains(ip)`.
- Keep the adapter so we can swap to a faster impl later (e.g. `treebitmap`) without touching evaluator.
- `IpAddr` is already imported across the codebase — same type used here.

## Requirements

### Functional
- `IpCidrTable::new()` → empty table.
- `IpCidrTable::insert_str(&str)` parses CIDR or single IP and inserts.
- `IpCidrTable::contains(IpAddr) -> bool`.
- `len() -> usize` for caps + metrics.

### Non-functional
- p99 lookup ≤ 2 µs at 10 k entries (validated in phase-07 bench).
- O(1) extra allocation per request — no allocations in `contains`.

## Architecture

```
   insert_str("10.0.0.0/8") ──► IpNet ──► (IpNetwork v4 | v6) ──► table.insert(_, ())
                                  │ ipnet → ip_network conversion
                                  ▼
   contains(192.168.1.1)  ──► table.longest_match(addr).is_some()
```

Single IP (`192.168.1.5`) is normalised to a `/32` (v4) or `/128` (v6).

## Related Code Files

### Create
- `crates/waf-engine/src/access/ip_table.rs`

### Modify
- `crates/waf-engine/src/access/mod.rs` — `pub use ip_table::IpCidrTable;`
- `crates/waf-engine/src/access/config.rs` — `AccessLists` gains `ip_whitelist: IpCidrTable`, `ip_blacklist: IpCidrTable`, build them in `from_yaml_*`.

## Implementation Steps

1. **Create `ip_table.rs`** with type alias and adapter:
   ```rust
   use std::net::IpAddr;
   use std::str::FromStr;
   use ip_network::IpNetwork;
   use ip_network_table::IpNetworkTable;

   pub struct IpCidrTable {
       table: IpNetworkTable<()>,
       len: usize,
   }
   impl IpCidrTable {
       pub fn new() -> Self { Self { table: IpNetworkTable::new(), len: 0 } }

       pub fn insert_str(&mut self, raw: &str) -> anyhow::Result<()> {
           let net = parse_cidr_or_ip(raw)?;
           // duplicate inserts return previous value; we ignore it.
           let _ = self.table.insert(net, ());
           self.len += 1;
           Ok(())
       }

       #[inline]
       pub fn contains(&self, ip: IpAddr) -> bool {
           self.table.longest_match(ip).is_some()
       }

       pub fn len(&self) -> usize { self.len }
       pub fn is_empty(&self) -> bool { self.len == 0 }
   }
   ```
2. **`parse_cidr_or_ip`** helper: try `IpNetwork::from_str(raw)` first, fall back to `IpAddr::from_str(raw)` and lift via `IpNetwork::new(ip, host_bits)?`.
3. **Wire into `AccessLists`** (extends phase-01 stub):
   ```rust
   pub struct AccessLists {
       pub(crate) ip_whitelist: IpCidrTable,
       pub(crate) ip_blacklist: IpCidrTable,
       // host_gate, tier_modes filled in later phases
       pub(crate) dry_run: bool,
   }
   impl AccessLists {
       pub fn from_yaml_str(s: &str) -> anyhow::Result<Arc<Self>> {
           let cfg: AccessConfig = serde_yaml::from_str(s).context("parse access-lists.yaml")?;
           cfg.validate()?;
           let mut wl = IpCidrTable::new();
           for s in &cfg.ip_whitelist { wl.insert_str(s).with_context(|| format!("ip_whitelist '{s}'"))?; }
           let mut bl = IpCidrTable::new();
           for s in &cfg.ip_blacklist { bl.insert_str(s).with_context(|| format!("ip_blacklist '{s}'"))?; }
           // host/tier built phase-03/04
           Ok(Arc::new(Self { ip_whitelist: wl, ip_blacklist: bl, dry_run: cfg.dry_run /* ... */ }))
       }
   }
   ```
4. **Compile-gate**: `cargo check -p waf-engine`.

## Todo List
- [x] Create `ip_table.rs` (≤ 100 LoC)
- [x] Implement `IpCidrTable::{new, insert_str, contains, len, is_empty}`
- [x] Implement `parse_cidr_or_ip` helper (single-IP + CIDR + dual-stack)
- [x] Extend `AccessLists` to own two `IpCidrTable`s
- [x] Build them in `AccessLists::from_yaml_str`
- [x] Unit tests: v4 hit, v6 hit, longest-prefix wins, miss, single-IP insert, malformed string returns error

## Success Criteria
- 6 unit tests pass:
  - `t_v4_hit`: `10.0.0.0/8` inserted, `10.1.2.3` → `true`
  - `t_v6_hit`: `2001:db8::/32` inserted, `2001:db8::1` → `true`
  - `t_longest_prefix_wins`: insert allow `/8`, deny `/24`; lookup `/24` ip; (semantics enforced by evaluator order in phase-04 — here both tables independently report match)
  - `t_miss`: `8.8.8.8` not in empty table → `false`
  - `t_single_ip`: `192.168.1.5` inserts as `/32`
  - `t_malformed`: `"not-an-ip"` → `Err`
- `cargo clippy -p waf-engine -- -D warnings` clean.
- File ≤ 200 LoC.

## Common Pitfalls
- **Mixing `ipnet` and `ip_network` crates**: workspace already uses `ipnet` for tier_match. `ip_network_table` requires `ip_network::IpNetwork` (different crate). Convert at the boundary; don't leak `ip_network` types into the public API.
- **Calling `contains` on `IpNetworkTable` directly returns `Option<&V>`**: use `longest_match(addr).is_some()` to be explicit and avoid `_unused_v` clippy warns.
- **Forgetting `#[inline]` on `contains`**: it's on the hot path; encourage inlining across the crate boundary.

## Risk Assessment
- Low. Single external dep, well-maintained.

## Security Considerations
- Bounded memory: caps enforced in phase-01 (50 k warn / 500 k bail).
- No regex or DNS — no ReDoS / DNS-amplification surface.

## Next Steps
- Phase 03: Host gate.
