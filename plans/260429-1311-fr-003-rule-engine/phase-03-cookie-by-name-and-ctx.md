# Phase 03 — Cookie-By-Name + RequestCtx.cookies

**Status:** complete  **Priority:** P0  **Effort:** 0.5d  **ACs:** AC-6 (cookie by name)

## Context Links
- Design: brainstorm §3.2, §3.4, §5 row 6
- Touch: `crates/waf-common/src/lib.rs`, `crates/waf-common/src/types.rs`, `crates/waf-engine/src/rules/engine.rs`

## Overview
Today `ConditionField::Cookie` returns whole `cookie:` header — can't match a single cookie by name. Add `Cookie(Option<String>)` (None = whole header for back-compat) and parse cookies once into `RequestCtx.cookies: HashMap<String, String>` so per-condition lookup is O(1).

## Key Insights
- Parse-once strategy: cookie parsing is expensive only relative to per-rule re-splitting; doing it at ctx build amortizes across all rules.
- RFC 6265 cookie name matching is **case-sensitive** (per unresolved Q2 — default decision).
- Back-compat: existing `Cookie` variant in DB JSON deserializes to `Cookie(None)` (full header).

## Requirements

### Functional
1. `RequestCtx.cookies: HashMap<String, String>` populated at ctx build from `headers["cookie"]`.
2. `ConditionField::Cookie(Option<String>)` — `None` returns whole header; `Some(name)` returns single cookie value or empty string.
3. AC-6: `field: cookie, name: session, op: eq, value: abc` matches `Cookie: session=abc; other=x`.
4. Existing rules with `Cookie` (legacy) deserialize to `Cookie(None)` — full-header semantics preserved.

### Non-Functional
- Parse cost: single-pass split on `; ` per request — O(n) on header length, runs once.
- No allocation per condition lookup beyond `&str` slice into the map.

## Architecture

```rust
// waf-common/src/types.rs
pub struct RequestCtx {
    // …existing
    pub cookies: HashMap<String, String>,   // parsed once
}

// engine.rs
pub enum ConditionField {
    // …
    Cookie(Option<String>),   // None → whole header (back-compat)
}
```

Cookie parser: `parse_cookie_header(&str) -> HashMap<String, String>` — splits on `;`, trims, splits first `=`. Malformed pairs skipped (no panic).

Serde back-compat: `Cookie` (no payload) and `Cookie: null` both deserialize to `Cookie(None)`. Use `#[serde(deserialize_with = ...)]` or test custom `Deserialize` impl.

## Related Code Files
**Modify:**
- `crates/waf-common/src/types.rs` — add `cookies` field to `RequestCtx` + cookie parser util.
- `crates/waf-common/src/lib.rs` — re-export if needed.
- `crates/waf-engine/src/rules/engine.rs` — `Cookie(Option<String>)` variant; `field_value()` arm; `compile_condition()` unchanged (matcher is field-agnostic).
- All `RequestCtx { … }` literal call sites — add `cookies: HashMap::new()` (or use `..Default::default()`).
- Any test fixtures constructing `RequestCtx`.

**Read for context:**
- `crates/gateway/src/proxy/ctx_builder.rs` (or equivalent) — where `RequestCtx` is built; populate `cookies` here.

## Implementation Steps
1. Add `parse_cookie_header(s: &str) -> HashMap<String, String>` in `waf-common::types` — pure fn, easy to unit test.
2. Add `RequestCtx.cookies` field; default `HashMap::new()` via `Default`.
3. Update gateway ctx builder to call parser if `cookie:` header present.
4. Change `ConditionField::Cookie` → `Cookie(Option<String>)`. Provide custom `Deserialize` for back-compat:
   - String `"cookie"` → `Cookie(None)`
   - Object `{cookie: {name: "session"}}` → `Cookie(Some("session".into()))`
5. Update `field_value()` arm:
   - `Cookie(None)` → `ctx.headers.get("cookie").cloned()`
   - `Cookie(Some(name))` → `ctx.cookies.get(name).cloned()`
6. Update YAML/JSON parsers to accept new shape (`name:` field on cookie). Defer full parser change to phase 04 (alongside nested tree).
7. Tests:
   - `parse_cookie_header_basic` (`a=1; b=2`)
   - `parse_cookie_header_malformed` (skip `=v`, `k=`, empty)
   - `cookie_by_name_matches` (AC-6)
   - `cookie_no_name_returns_full_header` (back-compat)
   - `cookie_legacy_deserializes_as_none`

## Todo
- [x] `parse_cookie_header()` util in waf-common
- [x] `RequestCtx.cookies` field + ctx builder populates it
- [x] `Cookie(Option<String>)` variant + custom serde
- [x] `field_value()` cookie-by-name path
- [x] 5+ unit tests pass (4 in waf-common, 5 in waf-engine)
- [x] All `RequestCtx { ... }` call sites compile

## Success Criteria
- AC-6 test passes.
- Legacy DB rules with `field: cookie` still match against full header.
- `cargo test -p waf-common -p waf-engine -p gateway` green.

## Security
- Reject cookie names containing `;`, `=`, control chars (defensive — malformed-skip in parser).
- Don't log cookie values (PII / session tokens).
