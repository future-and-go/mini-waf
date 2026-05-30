---
phase: 2
title: "Core Types + Injector Module"
status: completed
priority: P1
effort: "2h"
dependencies: [1]
---

# Phase 2: Core Types + Injector Module

## Overview
Implement the DRY core: `CacheStatus` enum, `WafHeaderValues` bundle, the single
`inject_waf_observability_headers()` function, and the FR-035 preserve-prefix default. Make Phase 1
unit tests pass.

## Requirements
- Functional: one function inserts all 6 headers with contract-exact names/values, clamps score, maps `None`→`none`, sanitizes CR/LF.
- Non-functional: zero `.unwrap()`; `&str` over `String` (Rule 7); no panic on bad header value.

## Architecture
New module `crates/gateway/src/waf_observability_headers.rs`, exported from `lib.rs`.

```rust
pub enum CacheStatus { Hit, Miss, Bypass }   // derive Default = Bypass (fail-safe)
impl CacheStatus { pub const fn as_contract_str(self) -> &'static str { /* HIT|MISS|BYPASS */ } }

pub struct WafHeaderValues<'a> {
    pub request_id: &'a str,
    pub risk_score: u8,
    pub action: &'a str,        // already WafAction::as_contract_str()
    pub rule_id: Option<&'a str>,
    pub mode: &'a str,          // already InteropMode::as_contract_str()
    pub cache: CacheStatus,
}

pub fn inject_waf_observability_headers(
    resp: &mut pingora_http::ResponseHeader,
    vals: &WafHeaderValues<'_>,
) -> pingora_core::Result<()> { /* insert 6, replace semantics */ }
```

## Related Code Files
- Create: `crates/gateway/src/waf_observability_headers.rs`
- Modify: `crates/gateway/src/lib.rs` (add `pub mod waf_observability_headers;`)
- Modify: FR-035 `HeaderFilterConfig` default (`waf-common/src/config.rs` or wherever `preserve_prefixes` lives) — add `"x-waf-"`
- Read for context: `crates/gateway/src/error_page/error_page_factory.rs` (insert_header + remove_header pattern), `crates/gateway/src/proxy_waf_response.rs`

## Implementation Steps
1. `CacheStatus` (derive `Clone, Copy, Debug, Default, PartialEq`; `#[default] Bypass`) + `as_contract_str`.
2. `WafHeaderValues<'a>`.
3. `inject_waf_observability_headers`:
   - `insert_header` (replace → idempotent) for each of the 6.
   - **Clamp** score: `vals.risk_score.min(100)` before formatting (red-team F11). Format via `u8::to_string` (no new dep).
   - rule_id: `vals.rule_id` → if `None` OR contains CR/LF/non-token char after a strip → emit `none` (never empty) (red-team F12).
   - request_id: trust UUID source but cheaply reject CR/LF (defensive; do not over-engineer per YAGNI).
   - Propagate `insert_header` errors with `?`.
4. Add `"x-waf-"` to FR-035 `preserve_prefixes` default so the global header_filter never strips contract headers (red-team F4).
5. Export from `lib.rs`. Run Phase 1 unit tests → green for the injector layer.

## Success Criteria
- [x] Phase 1 injector unit tests pass (incl. clamp + CRLF→`none`; Phase 3 Default::action test remains ignored by design)
- [x] `cargo clippy -p gateway -- -D warnings` clean; no `.unwrap()`/`.expect()` outside tests
- [x] `inject_*` is the ONLY function inserting X-WAF-* headers (grep verifies single production definition)
- [x] FR-035 `preserve_prefixes` default contains `"x-waf-"` (unit test on default config)

## Risk Assessment
- Risk: `insert_header` signature/lifetime mismatch → confirm against `error_page_factory.rs:36-43` call style.
- Risk: adding a dep for int formatting → use `to_string`; do NOT add `itoa`.

## Security Considerations
- CR/LF sanitization on `rule_id` (and defensively `request_id`) is mandatory — response-splitting defense, esp. for WAF-decision paths that bypass FR-035's own CRLF guard.
- `CacheStatus::default() == Bypass` (never falsely advertise HIT).
