# Phase 1 — Types + TOML Schema

## Context
- Design doc §6 (data model), §7 (TOML schema), §10 (AC mapping).
- Owner crate: `waf-common` (data types are shared; gateway + future engine consumers all read them).

## Why this phase first
Types are the contract. Every later phase imports them. Lock them now so classifier (Phase 2) and registry (Phase 3) can be built in parallel afterward without churn. Common junior trap: starting with the matcher logic and discovering halfway through that a field is missing — costs a refactor across files.

## Goals
- Define `Tier`, `TierPolicy`, `TierClassifierRule`, `TierConfig`, sub-types.
- TOML deserialization works on a fixture file.
- `validate()` rejects invalid configs (missing tier policy, bad regex, empty rule list).

## Files
- **Create:** `crates/waf-common/src/tier.rs`
- **Create:** `crates/waf-common/src/tier_match.rs` (matcher value types — kept separate to keep `tier.rs` < 200 LoC)
- **Modify:** `crates/waf-common/src/lib.rs` (re-export)
- **Modify:** `crates/waf-common/Cargo.toml` (add `regex` if not present)
- **Create fixture:** `crates/waf-common/tests/fixtures/tiered_protection.toml`

## Implementation Notes

### `Tier` enum
```rust
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier { Critical, High, Medium, CatchAll }

impl Tier {
    pub const ALL: [Tier; 4] = [Tier::Critical, Tier::High, Tier::Medium, Tier::CatchAll];
}
```
WHY `Copy`: tier is 1 byte; passing by value is cheaper than `&Tier`. WHY `ALL` const: validator iterates it to enforce all-tiers-have-policies.

### `FailMode`, `CachePolicy`, `RiskThresholds`
```rust
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailMode { Close, Open }

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum CachePolicy {
    NoCache,
    ShortTtl   { ttl_seconds: u32 },
    Aggressive { ttl_seconds: u32 },
    Default    { ttl_seconds: u32 },
}

#[derive(Clone, Copy, Debug, serde::Deserialize)]
pub struct RiskThresholds { pub allow: u32, pub challenge: u32, pub block: u32 }
```
WHY tag-based enum for `CachePolicy`: TOML inline tables read cleanly (`{ mode = "no_cache" }`).

### `TierPolicy`
Plain `Clone + Debug` struct holding the four fields above. No methods — it's pure data.

### Matchers (`tier_match.rs`)
```rust
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PathMatch  { Exact { value: String }, Prefix { value: String }, Regex { value: String } }

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HostMatch  { Exact { value: String }, Suffix { value: String }, Regex { value: String } }

#[derive(Clone, Debug, serde::Deserialize)]
pub struct HeaderMatch { pub name: String, pub value: String }   // MVP: exact value, case-insensitive name
```
**Note:** Regex variants store the source string here. Compilation happens in Phase 2 (classifier), to keep this module pure-data. Validation in `validate()` test-compiles them and discards the result.

### `TierClassifierRule`
Mirrors design doc §6.

### `TierConfig` + `validate()`
```rust
pub struct TierConfig {
    pub default_tier: Tier,
    pub classifier_rules: Vec<TierClassifierRule>,
    pub policies: HashMap<Tier, TierPolicy>,
}

impl TierConfig {
    pub fn validate(&self) -> Result<(), TierConfigError> {
        // 1. all 4 tiers in policies
        for t in Tier::ALL { if !self.policies.contains_key(&t) {
            return Err(TierConfigError::MissingPolicy(t));
        }}
        // 2. risk thresholds: allow < challenge < block
        // 3. compile all regexes (test only, discard)
        // 4. priority field non-zero or zero ok? Allow zero, sort stably.
        Ok(())
    }
}
```
WHY validate at load: we never want a malformed config silently in production. Fail loud, fail early. Common pitfall: validation scattered across consumers → bugs slip through.

### `TierConfigError`
Use `thiserror::Error`. Variants: `MissingPolicy(Tier)`, `BadRegex { rule_idx: usize, source: regex::Error }`, `InvalidThresholds { tier: Tier }`.

## TOML Fixture
Provide a complete valid config for tests (mirror design doc §7).

## Tests (this phase)
- `parses_valid_toml`
- `validate_rejects_missing_tier_policy`
- `validate_rejects_bad_regex`
- `validate_rejects_inverted_thresholds`
- `tier_serde_roundtrip`

## Acceptance
- `cargo test -p waf-common tier` all green.
- `cargo clippy -p waf-common -- -D warnings` clean.
- File sizes: `tier.rs` < 200 LoC, `tier_match.rs` < 100 LoC.

## Common Pitfalls
- Forgetting `#[serde(rename_all = "snake_case")]` → "catch_all" in TOML won't deserialize.
- Compiling regex in `Deserialize` impl → couples data to regex crate at deserialize time, kills testability. Keep compilation deferred.
- Returning `String` from match accessors → use `&str`. Per CLAUDE.md "Minimize allocations".

## Status
Complete. Merged in commit b6ebc92.
- `tier.rs` ✅ (enums + structs)
- `tier_match.rs` ✅ (matcher types)
- Re-exports in `lib.rs` ✅
- Fixture TOML ✅
- 5+ unit tests ✅
- All quality gates ✅

## Next
Phase 2 — build the classifier on top of these types.
