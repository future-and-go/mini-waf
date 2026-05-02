# Phase 01 — Module Skeleton & RateLimitStore Trait

**Priority:** P0 | **Status:** done | **Depends:** —
**Pattern reference:** `crates/waf-engine/src/device_fp/identity/identity_trait.rs`

## Goal

Create `rate_limit/` module tree and define `RateLimitStore` async trait + value types. No logic yet — types only, must compile.

## Requirements

- Async trait, `Send + Sync`
- `Decision` enum: `Allow | BurstExceeded | SustainedExceeded`
- `LimitCfg` struct: burst capacity/refill, window secs/limit
- `KeyKind` enum: `Ip(IpAddr) | Session(String)`
- All public items documented with `///`

## Files

**Create:**
- `crates/waf-engine/src/checks/rate_limit/mod.rs`
- `crates/waf-engine/src/checks/rate_limit/store/mod.rs`
- `crates/waf-engine/src/checks/rate_limit/algo/mod.rs`
- `crates/waf-engine/src/checks/rate_limit/key.rs`

**Modify:**
- `crates/waf-engine/src/checks/mod.rs` — `pub mod rate_limit;`

## Implementation

### `store/mod.rs`

```rust
use async_trait::async_trait;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    BurstExceeded,
    SustainedExceeded,
}

#[derive(Clone, Debug)]
pub struct LimitCfg {
    pub burst_capacity: u32,
    pub burst_refill_per_s: f64,
    pub window_secs: u32,
    pub window_limit: u32,
}

#[async_trait]
pub trait RateLimitStore: Send + Sync {
    /// Atomic refill TB + consume + update SW. Returns decision.
    async fn check_and_consume(
        &self,
        key: &str,
        cfg: &LimitCfg,
        now_ms: i64,
    ) -> anyhow::Result<Decision>;

    /// Sweep idle entries. Returns count purged. (No-op for Redis if EXPIRE used.)
    async fn purge_expired(&self) -> anyhow::Result<usize>;
}
```

### `key.rs`

```rust
use std::net::IpAddr;

pub enum KeyKind<'a> {
    Ip { host: &'a str, ip: IpAddr },
    Session { host: &'a str, session: &'a str },
}

impl<'a> KeyKind<'a> {
    pub fn render(&self) -> String {
        match self {
            Self::Ip { host, ip } => format!("ip:{host}:{ip}"),
            Self::Session { host, session } => format!("sess:{host}:{session}"),
        }
    }
}
```

### `mod.rs`

```rust
pub mod algo;
pub mod key;
pub mod store;

pub use store::{Decision, LimitCfg, RateLimitStore};
```

## Verify

```bash
cargo check -p waf-engine
cargo fmt --all -- --check
cargo clippy -p waf-engine -- -D warnings
```

## Done When

- [x] All files compile
- [x] No new clippy warnings
- [x] No public items without doc-comments
