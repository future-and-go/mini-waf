//! Tiered Protection — data types + TOML schema (FR-002 Phase 1).
//!
//! Pure data. No regex compilation, no I/O. Compilation lives in
//! `gateway::tiered` (Phase 2); this crate only validates that regex
//! sources *would* compile via `validate()`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::tier_match::{HeaderMatch, HostMatch, PathMatch};

/// Protection tier. Order is significant for fallback semantics, not for matching.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Critical,
    High,
    Medium,
    CatchAll,
}

impl Tier {
    /// All tiers — used by validator to enforce every tier has a policy.
    pub const ALL: [Self; 4] = [Self::Critical, Self::High, Self::Medium, Self::CatchAll];
}

/// What to do when a downstream check (rule eval, risk scorer) errors out.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    Close,
    Open,
}

/// Per-tier cache strategy. Tagged so TOML reads as `{ mode = "no_cache" }`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum CachePolicy {
    NoCache,
    ShortTtl { ttl_seconds: u32 },
    Aggressive { ttl_seconds: u32 },
    Default { ttl_seconds: u32 },
}

/// Risk-score cutoffs. Invariant (checked in `validate`): allow < challenge < block.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RiskThresholds {
    pub allow: u32,
    pub challenge: u32,
    pub block: u32,
}

/// HTTP method enum — kept here (not pulled from `http` crate) to keep
/// `waf-common` a leaf crate. Phase 2 builds a bitset over this.
#[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Connect,
    Options,
    Trace,
    Patch,
}

/// Full per-tier policy. Pure data.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TierPolicy {
    pub fail_mode: FailMode,
    pub ddos_threshold_rps: u32,
    pub cache_policy: CachePolicy,
    pub risk_thresholds: RiskThresholds,
}

/// Single classifier rule. Multi-field = AND (all conditions must match).
/// Higher `priority` wins on ties; sort happens in Phase 2 when compiling.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TierClassifierRule {
    pub priority: u32,
    pub tier: Tier,
    #[serde(default)]
    pub host: Option<HostMatch>,
    #[serde(default)]
    pub path: Option<PathMatch>,
    #[serde(default)]
    pub method: Option<Vec<HttpMethod>>,
    #[serde(default)]
    pub headers: Option<Vec<HeaderMatch>>,
}

/// Top-level tiered protection config. Lives under `[tiered_protection]` in TOML.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TierConfig {
    pub default_tier: Tier,
    #[serde(default)]
    pub classifier_rules: Vec<TierClassifierRule>,
    pub policies: HashMap<Tier, TierPolicy>,
}

/// Validation errors. Loud and specific — fail-fast at config load.
#[derive(Debug, thiserror::Error)]
pub enum TierConfigError {
    #[error("missing policy for tier {0:?}")]
    MissingPolicy(Tier),
    #[error("invalid risk thresholds for tier {tier:?}: require allow < challenge < block")]
    InvalidThresholds { tier: Tier },
    #[error("bad regex in classifier rule #{rule_idx}: {source}")]
    BadRegex {
        rule_idx: usize,
        #[source]
        source: regex::Error,
    },
}

impl TierConfig {
    /// Validate the config end-to-end. Run once at config load. Never panics.
    ///
    /// Checks:
    /// 1. every `Tier` has a `TierPolicy`
    /// 2. each policy's `RiskThresholds` satisfy allow < challenge < block
    /// 3. every regex source in matchers is compilable
    pub fn validate(&self) -> Result<(), TierConfigError> {
        for tier in Tier::ALL {
            let policy = self.policies.get(&tier).ok_or(TierConfigError::MissingPolicy(tier))?;
            let rt = &policy.risk_thresholds;
            if !(rt.allow < rt.challenge && rt.challenge < rt.block) {
                return Err(TierConfigError::InvalidThresholds { tier });
            }
        }

        for (idx, rule) in self.classifier_rules.iter().enumerate() {
            if let Some(src) = rule.path.as_ref().and_then(PathMatch::regex_source) {
                regex::Regex::new(src).map_err(|e| TierConfigError::BadRegex {
                    rule_idx: idx,
                    source: e,
                })?;
            }
            if let Some(src) = rule.host.as_ref().and_then(HostMatch::regex_source) {
                regex::Regex::new(src).map_err(|e| TierConfigError::BadRegex {
                    rule_idx: idx,
                    source: e,
                })?;
            }
        }

        Ok(())
    }
}
