# Phase 2 — Tier Classifier

## Context
- Design doc §4 (architecture), §6 (rule shape), §12 (perf risks).
- Depends on: Phase 1 types.

## Why this phase
The classifier is the *only* component that touches the request hot-path on every request. Performance and correctness here directly hit p99 latency (5ms budget). Junior trap: putting it inside the engine crate — but it needs Pingora request types, so it lives in `gateway`.

## Goals
- `TierClassifier::classify(&Request) -> Tier` returns a tier in O(rules) with pre-compiled regex.
- Priority-sorted; first match wins; default tier on no match.
- All four matcher kinds (path/host/method/header) work.

## Files
- **Create:** `crates/gateway/src/tiered/mod.rs` (façade re-exports)
- **Create:** `crates/gateway/src/tiered/tier_classifier.rs`
- **Create:** `crates/gateway/src/tiered/compiled_rule.rs` (pre-compiled rule with `regex::Regex`)
- **Modify:** `crates/gateway/src/lib.rs` (add `pub mod tiered;`)

## Implementation Notes

### Pre-compilation
Take `Vec<TierClassifierRule>` (from Phase 1) → produce `Vec<CompiledTierRule>` once at config load. Compiled rule replaces regex strings with `regex::Regex`. Sorted by `priority DESC` (higher wins).

```rust
pub struct CompiledTierRule {
    pub priority: u32,
    pub tier: Tier,
    pub host:    Option<CompiledHostMatch>,
    pub path:    Option<CompiledPathMatch>,
    pub method:  Option<MethodSet>,         // bitset, not Vec
    pub headers: Option<Vec<(HeaderName, HeaderValue)>>, // pre-parsed
}
```
WHY `MethodSet` bitset: 9 HTTP methods fit in a `u16`; lookup is one bitwise AND vs Vec scan.

### Classifier
```rust
pub struct TierClassifier {
    rules: Vec<CompiledTierRule>,
    default_tier: Tier,
}

impl TierClassifier {
    pub fn classify(&self, req: &RequestParts) -> Tier {
        for r in &self.rules {
            if r.matches(req) { return r.tier; }
        }
        self.default_tier
    }
}
```
**`RequestParts`**: thin borrowed view (`&str` path, `&str` host, `Method`, `&HeaderMap`) — avoids tying classifier to Pingora types directly so we can unit-test without spinning up a session. Build it from Pingora request in Phase 5.

### Matcher semantics (locked)
- Path `Exact`: byte-equal.
- Path `Prefix`: `path.starts_with(value)`.
- Path `Regex`: `regex.is_match(path)`.
- Host `Exact`: byte-equal (lowercased once at compile).
- Host `Suffix`: `host.ends_with(value)`.
- Host `Regex`: `regex.is_match(host)`.
- Method: bitset contains.
- Header name: ASCII-lowercase compared (HTTP spec).
- Header value: byte-equal (case-sensitive — case sensitivity decision per design doc §15 unresolved Q1; default sensitive, document).

A rule with multiple match fields = **AND** (all conditions must hold). No OR; multi-OR cases require multiple rules with same tier — keeps the model simple.

## Tests
- `priority_higher_wins_when_multiple_match`
- `default_tier_when_no_match`
- `path_exact_prefix_regex_each_match`
- `host_suffix_match`
- `method_bitset_match`
- `header_match_exact`
- `combined_path_method_must_all_match` (AND semantics)
- Property test (quickcheck): random rule sets always classify in O(n) without panicking.

## Bench (deferred to Phase 6 but design now)
Criterion bench: 50-rule config, 1000 random requests. Target < 50µs per `classify`.

## Acceptance
- `cargo test -p gateway tiered::` green.
- `cargo clippy -p gateway -- -D warnings` clean.
- Files all < 200 LoC.

## Common Pitfalls
- **Compiling regex per request** = 1000× slower. Always pre-compile.
- **`Vec<Method>` lookup** instead of bitset → linear scan on hot-path. Use bitset.
- **Forgetting case-folding on header names** → `Content-Type` won't match `content-type`. HTTP says case-insensitive.
- **Stable sort vs unstable** → use stable so rule order in TOML breaks ties predictably.

## Todo
- [x] `compiled_rule.rs` with `MethodSet`, compile fn from Phase 1 types
- [x] `tier_classifier.rs` with `classify`
- [x] `RequestParts` borrowed view
- [x] 7 unit tests + property test (delivered: 8 unit + 1 property-style)
- [x] mod.rs re-exports

## Status
Complete. Merged in commit 72b9e3b.
- Compiles clean ✅
- 9/9 unit + property tests green ✅
- Clippy clean ✅
- Files properly scoped (<200 LoC) ✅
- `thiserror` added to deps ✅

## Next
Phase 3 — registry that holds tier→policy and the classifier together.
