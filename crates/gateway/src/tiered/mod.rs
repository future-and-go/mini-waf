//! Tiered protection — request-tier classification (FR-002 Phase 2).
//!
//! Compiled rule forms + classifier. Lives in `gateway` (not `waf-engine`)
//! because Phase 5 will wire it to Pingora request types.

pub mod compiled_rule;
pub mod tier_classifier;

pub use compiled_rule::{
    CompileError, CompiledHostMatch, CompiledPathMatch, CompiledTierRule, MethodSet, compile_rule, compile_rules,
};
pub use tier_classifier::{RequestParts, TierClassifier};
