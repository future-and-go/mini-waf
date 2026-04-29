//! Tiered protection — request-tier classification (FR-002 Phase 2).
//!
//! Compiled rule forms + classifier. Lives in `gateway` (not `waf-engine`)
//! because Phase 5 will wire it to Pingora request types.

pub mod compiled_rule;
pub mod tier_classifier;
pub mod tier_config_watcher;
pub mod tier_policy_registry;

pub use compiled_rule::{
    CompileError, CompiledHostMatch, CompiledPathMatch, CompiledTierRule, MethodSet, compile_rule, compile_rules,
};
pub use tier_classifier::{RequestParts, TierClassifier};
pub use tier_config_watcher::{DEFAULT_DEBOUNCE_MS, TierConfigWatcher, WatcherError};
pub use tier_policy_registry::{SnapshotBuildError, TierPolicyRegistry, TierSnapshot};
