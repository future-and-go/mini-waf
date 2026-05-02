//! FR-004 rate-limiting module.
//!
//! Composed of:
//! - [`store`]   — async `RateLimitStore` trait + value types
//! - [`algo`]    — token-bucket / sliding-window logic
//! - [`key`]     — key construction (`ip:<host>:<ip>`, `sess:<host>:<id>`)
//! - [`check`]   — `RateLimitCheck` integrating store + key into the WAF pipeline

use std::collections::HashMap;

use waf_common::tier::Tier;

use store::LimitCfg;

pub mod algo;
pub mod check;
pub mod key;
pub mod store;

pub use check::RateLimitCheck;
pub use store::{Decision, RateLimitStore};

/// Per-deployment rate-limit configuration.
///
/// Maps each protection tier to a `LimitCfg`. Tiers without an explicit entry
/// are skipped (no rate limit applied for that tier). `session_cookie` names
/// the cookie whose value identifies a session for the per-session key.
#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    /// Cookie name to read for session identity (case-sensitive per RFC 6265).
    pub session_cookie: String,
    /// Per-tier limit configurations. Missing tiers ⇒ no per-request limit.
    pub tiers: HashMap<Tier, LimitCfg>,
}

impl RateLimitConfig {
    /// Look up the limit cfg for a given tier, if any.
    #[must_use]
    pub fn for_tier(&self, tier: Tier) -> Option<&LimitCfg> {
        self.tiers.get(&tier)
    }
}

impl Default for RateLimitConfig {
    /// Empty config — no tiers limited. Phase 07 wires real config; until then
    /// this default keeps the check inert when registered into the pipeline.
    fn default() -> Self {
        Self {
            session_cookie: "SESSIONID".to_string(),
            tiers: HashMap::new(),
        }
    }
}
