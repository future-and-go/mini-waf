//! FR-012 phase-02 — `Classifier` strategy trait.
//!
//! Each classifier inspects an [`ActorTxSnapshot`] (cloned out of the
//! `DashMap` shard so no guard is held during evaluation) and returns
//! `Some(Signal)` when its rule fires. The recorder runs all classifiers
//! every record-call (gated by a per-actor cooldown).
//!
//! Mirrors `device_fp::SignalProvider` (FR-010) but stays inside this
//! module to keep the velocity-feature concerns local.

use crate::device_fp::signal::Signal;

use super::config::TxVelocityConfig;
use super::recorder::ActorTxSnapshot;

pub trait Classifier: Send + Sync {
    /// Stable short name used in logs / metrics.
    fn name(&self) -> &'static str;

    /// Return `Some(Signal)` if the actor's recent history matches the rule.
    /// `now_ms` is monotonic ms (recorder's clock), `cfg` is the live
    /// config snapshot — implementations read thresholds straight from it
    /// so hot-reloads take effect without rebuilding the classifier list.
    fn evaluate(&self, snap: &ActorTxSnapshot, now_ms: u64, cfg: &TxVelocityConfig) -> Option<Signal>;
}
