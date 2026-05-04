//! FR-012 phase-02 — concrete `Classifier` implementations.
//!
//! Three strategies match the three attack patterns documented in the FR-012
//! brainstorm: sequence timing, withdrawal velocity, limit-change burst.
//! Each is a unit struct (zero state) — thresholds live in
//! `TxVelocityConfig` and are read on every evaluate.

pub mod limit_change_burst;
pub mod sequence_timing;
pub mod withdrawal_velocity;

pub use limit_change_burst::LimitChangeBurstClassifier;
pub use sequence_timing::SequenceTimingClassifier;
pub use withdrawal_velocity::WithdrawalVelocityClassifier;

use std::sync::Arc;

use super::classifier::Classifier;
use super::config::TxVelocityConfig;

/// Build the default classifier list.
///
/// Includes one classifier per configured block; missing config entries
/// simply yield no signals at runtime (the classifier short-circuits on
/// its own knob), so we keep the list shape stable across hot-reloads.
#[must_use]
pub fn default_classifiers(_cfg: &TxVelocityConfig) -> Vec<Arc<dyn Classifier>> {
    vec![
        Arc::new(SequenceTimingClassifier),
        Arc::new(WithdrawalVelocityClassifier),
        Arc::new(LimitChangeBurstClassifier),
    ]
}
