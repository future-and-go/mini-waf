# Phase 01 — Config Types & Engine Module Registration

**Priority:** P0 — gating phase
**Status:** completed

## Goal

Make `waf-engine::outbound::HeaderFilter` compile and be reachable from outside the crate, with a config type wired into `AppConfig`.

## Context Links

- Requirement: `analysis/requirements.md` line 75 (FR-035)
- Existing skeleton: `crates/waf-engine/src/outbound/header_filter.rs`
- Existing module file (broken): `crates/waf-engine/src/outbound/mod.rs`
- Config home: `crates/waf-common/src/config.rs`
- Module registry: `crates/waf-engine/src/lib.rs`
- Research: `research/researcher-01-header-leak-prevention.md` §2 (default strip list), §3 (PII patterns)

## Files

**Modify:**
- `crates/waf-common/src/config.rs` — add `OutboundConfig`, `HeaderFilterConfig`; embed `outbound: OutboundConfig` in `AppConfig`
- `crates/waf-engine/src/outbound/mod.rs` — drop FR-033/FR-034 references; expose only `HeaderFilter`
- `crates/waf-engine/src/lib.rs` — register `pub mod outbound;` and re-export `HeaderFilter`, `OutboundConfig`

**Delete (out of scope — FR-033/FR-034 belong to separate plans):**
- `crates/waf-engine/src/outbound/body_redactor.rs`
- `crates/waf-engine/src/outbound/response_filter.rs`

**Read for context:**
- `crates/waf-common/src/config.rs` — existing config patterns (e.g. `CacheConfig`, `SecurityConfig`)
- `crates/waf-engine/src/outbound/header_filter.rs` — current `HeaderFilterConfig` field expectations

## Config Schema

Add to `waf-common/src/config.rs`:

```rust
/// FR-035 outbound protection — currently scoped to response-header leak prevention.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundConfig {
    /// Master toggle. When false, no outbound filtering runs (zero overhead).
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub headers: HeaderFilterConfig,
}

impl Default for OutboundConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            headers: HeaderFilterConfig::default(),
        }
    }
}

/// FR-035 — response header leak prevention.
///
/// Detection categories (server-info / debug / error / PII) are hard-coded;
/// each category is gated by a boolean toggle so operators can enable only
/// what they need. User-supplied `strip_headers` / `strip_prefixes` extend
/// the built-in lists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderFilterConfig {
    /// Strip `Server`, `X-Powered-By`, `X-AspNet-Version`, etc.
    #[serde(default = "default_true")]
    pub strip_server_info: bool,
    /// Strip headers with prefixes `X-Debug-`, `X-Internal-`, `X-Backend-`, `X-Real-IP`, `X-Forwarded-Server`.
    #[serde(default = "default_true")]
    pub strip_debug_headers: bool,
    /// Strip headers with prefixes `X-Error-`, `X-Exception-`, `X-Stack-`, `X-Trace-`.
    #[serde(default = "default_true")]
    pub strip_error_detail: bool,
    /// Scan header VALUES for PII patterns (email, credit card, SSN, phone, RFC-1918 IP).
    /// Off by default — adds regex cost per header per response.
    #[serde(default)]
    pub detect_pii_in_values: bool,
    /// Extra exact header names to strip (case-insensitive).
    #[serde(default)]
    pub strip_headers: Vec<String>,
    /// Extra header-name prefixes to strip (case-insensitive).
    #[serde(default)]
    pub strip_prefixes: Vec<String>,
}

fn default_true() -> bool { true }

impl Default for HeaderFilterConfig {
    fn default() -> Self {
        Self {
            strip_server_info: true,
            strip_debug_headers: true,
            strip_error_detail: true,
            detect_pii_in_values: false,
            strip_headers: Vec::new(),
            strip_prefixes: Vec::new(),
        }
    }
}
```

Embed in `AppConfig`:

```rust
#[serde(default)]
pub outbound: OutboundConfig,
```

## Implementation Steps

1. **Read** `waf-common/src/config.rs` to confirm import order and module conventions; mirror them.
2. **Add** `OutboundConfig` and `HeaderFilterConfig` to `config.rs` per schema above. Place after `SecurityConfig` for thematic grouping.
3. **Embed** `pub outbound: OutboundConfig` in `AppConfig` with `#[serde(default)]`.
4. **Delete** `crates/waf-engine/src/outbound/body_redactor.rs` and `crates/waf-engine/src/outbound/response_filter.rs`. They belong to FR-033/FR-034 plans.
5. **Rewrite** `crates/waf-engine/src/outbound/mod.rs` to a minimal form:
   ```rust
   //! Outbound response protection — FR-035 (header leak prevention).
   pub mod header_filter;
   pub use header_filter::HeaderFilter;
   ```
6. **Verify** `header_filter.rs` compiles against the new `HeaderFilterConfig`. The existing field names must match; if drift exists, align field names in the schema (do NOT rename in code without reason).
7. **Register** module in `crates/waf-engine/src/lib.rs`:
   ```rust
   pub mod outbound;
   pub use outbound::HeaderFilter;
   ```
8. **Run** `cargo check -p waf-common -p waf-engine` and fix until clean.
9. **Run** `cargo clippy -p waf-common -p waf-engine -- -D warnings`.

## Verification

- `cargo check --workspace` exits 0
- `cargo test -p waf-engine outbound::header_filter::tests::` — pre-existing 7 tests still green
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean

## Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| Schema drift between `header_filter.rs` and new `HeaderFilterConfig` | Step 6: read both, align field names before commit |
| Untracked deletion loses FR-033/FR-034 design notes | Files are git-untracked WIP — not "loss"; separate plan will re-add when scoped properly |
| Breaking serde deserialization of existing TOMLs | All new fields `#[serde(default)]`; root field also `#[serde(default)]` — old TOMLs still parse |

## Success Criteria

- [x] `cargo check --workspace` green
- [x] `cargo clippy ... -D warnings` green (touched crates)
- [x] Existing `header_filter.rs` unit tests still pass
- [x] `OutboundConfig::default()` returns a fully disabled state (master toggle off)
- [x] FR-033/FR-034 files removed cleanly (no stale `pub mod` lines)

## Next Phase

→ phase-02-gateway-wiring.md (hook `HeaderFilter` into Pingora `response_filter`)
