---
phase: 1
title: "Config Schema + Defaults"
status: pending
priority: P0
effort: "2h"
dependencies: []
---

# Phase 1: Config Schema + Defaults

## Overview

Add 6 optional upstream-timeout fields to `HostConfig` with serde defaults matching industry norms. Add a single validator: `connection_timeout_ms ≤ total_connection_timeout_ms`. Zero behavior change — Phase 2 wires these into Pingora.

## Requirements

**Functional:**
- New fields on `HostConfig` (all `u64` ms, all `#[serde(default = "...")]`):
  - `upstream_connect_timeout_ms` (default 5000)
  - `upstream_total_connection_timeout_ms` (default 10000)
  - `upstream_read_timeout_ms` (default 30000)
  - `upstream_write_timeout_ms` (default 10000)
  - `upstream_idle_timeout_ms` (default 60000)
  - `upstream_circuit_503_retry_after_s` (default 5, type `u32`)
- TOML round-trip safe (deserialize → serialize → deserialize is idempotent)
- Validator runs at config load (`HostConfig::validate()` or load entrypoint) — fails loud if `connect > total_connection`

**Non-functional:**
- No allocation on hot path (timeouts are `Copy` u64)
- All defaults inline `const fn` (no heap)
- Backward-compatible: existing configs without these fields parse OK

## Architecture

```rust
// crates/waf-common/src/types.rs
pub struct HostConfig {
    // ... existing fields ...

    /// FR-039: Pingora upstream TCP handshake timeout.
    #[serde(default = "default_upstream_connect_timeout_ms")]
    pub upstream_connect_timeout_ms: u64,

    /// FR-039: TCP + TLS handshake total timeout. MUST be ≥ connect.
    #[serde(default = "default_upstream_total_connection_timeout_ms")]
    pub upstream_total_connection_timeout_ms: u64,

    /// FR-039: Per-read timeout (resets after each read; safe for streaming).
    #[serde(default = "default_upstream_read_timeout_ms")]
    pub upstream_read_timeout_ms: u64,

    /// FR-039: Per-write timeout.
    #[serde(default = "default_upstream_write_timeout_ms")]
    pub upstream_write_timeout_ms: u64,

    /// FR-039: Idle connection pool reuse timeout.
    #[serde(default = "default_upstream_idle_timeout_ms")]
    pub upstream_idle_timeout_ms: u64,

    /// FR-039: Retry-After header value (seconds) on 503 responses.
    #[serde(default = "default_upstream_circuit_503_retry_after_s")]
    pub upstream_circuit_503_retry_after_s: u32,
}

const fn default_upstream_connect_timeout_ms() -> u64 { 5_000 }
const fn default_upstream_total_connection_timeout_ms() -> u64 { 10_000 }
const fn default_upstream_read_timeout_ms() -> u64 { 30_000 }
const fn default_upstream_write_timeout_ms() -> u64 { 10_000 }
const fn default_upstream_idle_timeout_ms() -> u64 { 60_000 }
const fn default_upstream_circuit_503_retry_after_s() -> u32 { 5 }
```

**Validator** (in `config.rs` or `types.rs`):

```rust
#[derive(Debug, thiserror::Error)]
pub enum HostConfigError {
    #[error("upstream_connect_timeout_ms ({connect}) > upstream_total_connection_timeout_ms ({total}); connect must be ≤ total")]
    ConnectExceedsTotal { connect: u64, total: u64 },
}

impl HostConfig {
    pub fn validate_upstream_timeouts(&self) -> Result<(), HostConfigError> {
        if self.upstream_connect_timeout_ms > self.upstream_total_connection_timeout_ms {
            return Err(HostConfigError::ConnectExceedsTotal {
                connect: self.upstream_connect_timeout_ms,
                total: self.upstream_total_connection_timeout_ms,
            });
        }
        Ok(())
    }
}
```

Wire validator into existing config-load path (find via grep `HostConfig::` callers in `gateway/src/router.rs` or `waf-storage` load path).

## Related Code Files

**Create:** none
**Modify:**
- `crates/waf-common/src/types.rs` — add 6 fields + 6 `const fn` defaults + `validate_upstream_timeouts()`
- `crates/waf-common/src/config.rs` or existing host-load path — invoke validator at load
- `configs/default.toml` — add commented block with defaults documenting each field

**Delete:** none

## Implementation Steps

1. Open `crates/waf-common/src/types.rs`; find `pub struct HostConfig` (~line 196).
2. Add 6 fields with `#[serde(default = "...")]` AFTER existing `body_mask_max_bytes` (preserves field-order stability).
3. Add 6 `const fn default_upstream_*()` helpers at end of file (mirror existing `default_*` helpers).
4. Add `HostConfigError` enum + `validate_upstream_timeouts()` impl.
5. Find the config-load entrypoint (`grep -rn 'HostConfig' crates/waf-storage/src/ crates/gateway/src/router.rs`); call `validate_upstream_timeouts()` there. **If validator finds no natural home in load path, defer to Phase 2** — invoke in `upstream_peer()` once + cache via `tracing::warn!` (do NOT panic; FR-039 is fail-safe).
6. Add commented defaults block to `configs/default.toml` under each `[[hosts]]` example (or `[hosts.upstream_timeouts]` sub-table — match existing TOML style).
7. Run `cargo check -p waf-common -p gateway` — must compile clean.
8. Run `cargo fmt --all` and `cargo clippy -p waf-common -- -D warnings`.

## Todo List

- [ ] Add 6 fields to `HostConfig`
- [ ] Add 6 `const fn` defaults
- [ ] Add `HostConfigError::ConnectExceedsTotal` + `validate_upstream_timeouts()`
- [ ] Wire validator into load path (or document deferral)
- [ ] Update `configs/default.toml` with commented defaults
- [ ] `cargo check -p waf-common -p gateway` green
- [ ] `cargo fmt --all` + `cargo clippy -- -D warnings` green
- [ ] Unit test: validator catches `connect > total`
- [ ] Unit test: defaults applied when fields omitted in TOML
- [ ] Unit test: explicit values override defaults

## Success Criteria

- [ ] Existing tests still pass: `cargo test -p waf-common`
- [ ] New tests for validator + defaults pass (≥ 3 cases)
- [ ] No new clippy warnings
- [ ] `HostConfig::default()` (if any) sets timeouts to documented defaults

## Risk Assessment

| Risk | Mitigation |
|------|-----------|
| Field-order break in TOML serialization | Append fields at end of struct; serde preserves declaration order |
| `const fn` not allowed for `u32`/`u64` literals in older Rust | Rust 2024 + edition 2024 supports; CI runs same toolchain |
| Hidden caller of `HostConfig::new()` breaks | `grep -rn 'HostConfig {' crates/` to find struct-literal constructors; add new fields with defaults |

## Test Strategy

Inline tests in `types.rs` (existing pattern):

```rust
#[test]
fn host_config_default_timeouts_present() {
    let toml = r#"
        code = "x"
        host = "h"
        port = 80
        ssl = false
        guard_status = true
        remote_host = "r"
        remote_port = 80
        start_status = true
        exclude_url_log = []
        is_enable_load_balance = false
        load_balance_strategy = "round_robin"
        defense_config = {}
        log_only_mode = false
    "#;
    let cfg: HostConfig = toml::from_str(toml).unwrap();
    assert_eq!(cfg.upstream_connect_timeout_ms, 5_000);
    assert_eq!(cfg.upstream_circuit_503_retry_after_s, 5);
}

#[test]
fn validator_rejects_connect_greater_than_total() {
    let mut cfg = sample_hostconfig();
    cfg.upstream_connect_timeout_ms = 20_000;
    cfg.upstream_total_connection_timeout_ms = 10_000;
    assert!(cfg.validate_upstream_timeouts().is_err());
}
```
