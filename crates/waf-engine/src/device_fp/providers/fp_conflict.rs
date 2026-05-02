//! Same fingerprint observed under multiple UAs — phase-02 stub.

use crate::device_fp::providers::SignalProvider;
use crate::device_fp::signal::Signal;
use crate::device_fp::types::DeviceCtx;

#[derive(Debug, Default)]
pub struct FpConflictProvider;

impl SignalProvider for FpConflictProvider {
    fn name(&self) -> &'static str {
        "fp_conflict"
    }
    fn evaluate(&self, _ctx: &DeviceCtx<'_>) -> Vec<Signal> {
        Vec::new()
    }
}
