//! FR-012 transaction-velocity & sequence module.
//!
//! Phase 1 scaffolding: types, config, role tagger, session-key extractor,
//! and recorder (`DashMap` + ring buffer + janitor). Classifiers and
//! `RiskAggregator` integration arrive in later phases.
//!
//! Mirrors `device_fp::behavior` (FR-011) and `checks::rate_limit`
//! (FR-004) — DRY by design.

pub mod check;
pub mod classifier;
pub mod classifiers;
pub mod config;
pub mod recorder;
pub mod role_tagger;
pub mod session_key;

pub use check::TxVelocityCheck;
pub use classifier::Classifier;
pub use classifiers::{
    LimitChangeBurstClassifier, SequenceTimingClassifier, WithdrawalVelocityClassifier, default_classifiers,
};
pub use config::{TxVelocityConfig, TxVelocityFileConfig, TxVelocityReloader};
pub use recorder::{ActorTxSnapshot, TxStore};
pub use role_tagger::RoleTagger;
pub use session_key::{SessionIdent, SessionKey, extract_session_key};

use serde::{Deserialize, Serialize};
use waf_common::Outcome;

/// Endpoint roles tracked by the velocity classifiers. Path → role mapping
/// lives in `TxVelocityConfig::endpoint_roles` (regex, hot-reloadable).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointRole {
    Login,
    Otp,
    Deposit,
    Withdrawal,
    LimitChange,
    /// No configured role matched this path. Recorder skips tracking.
    #[default]
    None,
}

/// One observed transaction-relevant request. `ts_ms` is monotonic ms
/// since the recorder's anchor `Instant` (NOT wall clock) — wall-clock
/// jumps cannot produce negative intervals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Event {
    pub role: EndpointRole,
    pub ts_ms: u64,
    /// Tristate outcome: `Pending` at record time, flipped to `Ok`/`Failed`
    /// by `set_outcome` on response. Classifiers ignore `Pending` events.
    pub outcome: Outcome,
}
