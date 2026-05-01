# Phase 01 — Schema, Types & Builder

## Context Links
- Design: [`../reports/brainstorm-260429-2222-fr-008-whitelist-blacklist.md`](../reports/brainstorm-260429-2222-fr-008-whitelist-blacklist.md) §5, §6
- Tier types reused: `crates/waf-common/src/tier.rs`

## Overview
**Priority:** P0 · **Status:** completed · **Effort:** 0.5 d

Define the public data model for the access subsystem and a YAML parser. **No I/O, no traits yet** — this phase exists so every later phase compiles independently against stable types.

## Key Insights
- Re-use `waf_common::tier::Tier` enum (4 variants) — do **not** redefine.
- `WhitelistMode` is **Strategy pattern**: enum-dispatch beats trait objects for two-variant hot-path.
- D4 (empty=disabled) lives in the parser default path: `Option<Vec<String>>` → empty `Vec` if missing.

## Requirements

### Functional
- Parse `rules/access-lists.yaml` matching brainstorm §5 schema verbatim.
- Reject malformed YAML with actionable error context (`anyhow::Context`).
- Soft cap warn at 50 000 entries, hard reject at 500 000 (risk register §7).
- `dry_run: bool` top-level optional (default `false`) — covered in phase-04.

### Non-functional
- Zero panic paths. No `.unwrap()` outside `#[cfg(test)]`.
- File ≤ 200 LoC per CLAUDE.md modularization rule. Split if exceeded.

## Architecture

```
AccessConfig (serde-derived, owns YAML shape)
    │ build()
    ▼
AccessLists (immutable runtime aggregate, Arc-shared)
    ├── ip_whitelist: IpCidrTable      ── phase-02
    ├── ip_blacklist: IpCidrTable      ── phase-02
    ├── host_gate:    HostGate         ── phase-03
    ├── tier_modes:   [WhitelistMode; 4]
    └── dry_run:      bool
```

Builder pattern: `AccessLists::from_yaml_path(p)?` and `AccessLists::from_yaml_str(s)?` — both return fully-validated snapshot or `Err`.

## Related Code Files

### Create
- `crates/waf-engine/src/access/mod.rs` — re-exports + `AccessDecision` enum
- `crates/waf-engine/src/access/config.rs` — serde structs + `from_yaml_*` constructors
- `crates/waf-engine/Cargo.toml` — add `ip_network_table = "0.2"` (used in phase-02 but added now)

### Modify
- `crates/waf-engine/src/lib.rs` — add `pub mod access;`

## Implementation Steps

1. **Add dep** to `crates/waf-engine/Cargo.toml`:
   ```toml
   ip_network_table = "0.2"
   ```
2. **Create `access/mod.rs`** with public surface:
   ```rust
   pub mod config;
   pub mod ip_table;     // stub for phase-02
   pub mod host_gate;    // stub for phase-03
   pub mod evaluator;    // stub for phase-04

   pub use config::{AccessConfig, AccessLists, WhitelistMode};
   pub use evaluator::AccessDecision;
   ```
3. **Define `WhitelistMode`** (Strategy enum) in `config.rs`:
   ```rust
   #[derive(Copy, Clone, Debug, Eq, PartialEq, serde::Deserialize)]
   #[serde(rename_all = "snake_case")]
   pub enum WhitelistMode {
       FullBypass,      // skip all downstream checks
       BlacklistOnly,   // run rules even if whitelisted
   }
   impl Default for WhitelistMode {
       fn default() -> Self { Self::BlacklistOnly } // safe default
   }
   ```
4. **Define raw `AccessConfig`** mirroring YAML 1:1:
   ```rust
   #[derive(Debug, Default, serde::Deserialize)]
   pub struct AccessConfig {
       #[serde(default)] pub version: u32,
       #[serde(default)] pub dry_run: bool,
       #[serde(default)] pub ip_whitelist: Vec<String>,
       #[serde(default)] pub ip_blacklist: Vec<String>,
       #[serde(default)] pub host_whitelist: HashMap<Tier, Vec<String>>,
       #[serde(default)] pub tier_whitelist_mode: HashMap<Tier, WhitelistMode>,
   }
   ```
5. **Stub `AccessLists`** (filled by later phases) but expose constructor signature now:
   ```rust
   pub struct AccessLists { /* fields filled phase-02..04 */ }
   impl AccessLists {
       pub fn from_yaml_str(s: &str) -> anyhow::Result<Arc<Self>> { /* todo phase-04 */ }
       pub fn from_yaml_path(p: &Path) -> anyhow::Result<Arc<Self>> { /* read+from_yaml_str */ }
       pub fn empty() -> Arc<Self> { /* all gates disabled */ }
   }
   ```
   Use `unimplemented!()` only inside `#[cfg(test)] fn` shims if needed; production paths must compile to a real (possibly empty) value — no `todo!()`/`unimplemented!()` in shipped code (Iron Rule #3).
6. **Validation rules** in `AccessConfig::validate(&self)`:
   - `version == 1` (else `anyhow::bail!`)
   - Each CIDR string parses via `IpNet::from_str` (deferred actual table-build to phase-02; just syntax-check here).
   - Total entries `> 500_000` → `bail!`; `> 50_000` → `tracing::warn!`.
   - Host strings: lowercase, no port suffix (`':'`), no whitespace — `bail!` otherwise.
7. **Run** `cargo check -p waf-engine` — must pass clean.

## Todo List
- [x] Add `ip_network_table = "0.2"` dep
- [x] Create `access/mod.rs` with module skeleton + `pub use`
- [x] Implement `AccessConfig` serde structs in `config.rs`
- [x] Implement `WhitelistMode` enum + `Default`
- [x] Implement `AccessConfig::validate()` (version, syntax, caps, host hygiene)
- [x] Implement `AccessLists::empty()` returning Arc-wrapped disabled snapshot
- [x] `cargo check -p waf-engine` clean
- [x] `cargo fmt && cargo clippy -p waf-engine -- -D warnings`

## Success Criteria
- `cargo check -p waf-engine` passes.
- Unit test: round-trip parse of brainstorm §5 sample YAML produces non-error `AccessConfig` with correct field counts.
- Unit test: missing `tier_whitelist_mode.medium` defaults to `BlacklistOnly`.
- Unit test: `version: 2` fails with descriptive error.
- Unit test: 500 001-entry blacklist rejected; 50 001-entry warns (capture logs).

## Common Pitfalls
- **Serde `#[serde(default)]` on `HashMap<Tier, _>`**: requires `Tier: Eq + Hash + Deserialize` — already true.
- **Forgetting `Default` on `WhitelistMode`**: serde fills missing tier entries with `Default`; default must be the **safer** of the two (`BlacklistOnly`).
- **CIDR validation deferred**: just syntax check here; the actual trie insert is phase-02 responsibility.

## Risk Assessment
- Low. Pure data + parsing.

## Security Considerations
- `serde_yaml` handles untrusted input — already vetted in FR-003. No additional surface.

## Next Steps
- Phase 02: implement `IpCidrTable` adapter and finish `AccessLists` IP fields.
