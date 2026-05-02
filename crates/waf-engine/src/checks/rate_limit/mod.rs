//! FR-004 rate-limiting module.
//!
//! Composed of three concerns:
//! - [`store`]   — async `RateLimitStore` trait + value types (this phase)
//! - [`algo`]    — token-bucket / sliding-window logic (later phases)
//! - [`key`]     — key construction (`ip:<host>:<ip>`, `sess:<host>:<id>`)

pub mod algo;
pub mod key;
pub mod store;

pub use store::{Decision, LimitCfg, RateLimitStore};
