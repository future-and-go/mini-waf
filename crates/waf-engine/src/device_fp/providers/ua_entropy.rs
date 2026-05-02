//! User-Agent Shannon entropy below threshold — phase-02 stub.

use crate::device_fp::providers::SignalProvider;
use crate::device_fp::signal::Signal;
use crate::device_fp::types::DeviceCtx;

#[derive(Debug, Default)]
pub struct UaEntropyProvider;

impl SignalProvider for UaEntropyProvider {
    fn name(&self) -> &'static str {
        "ua_entropy"
    }
    fn evaluate(&self, _ctx: &DeviceCtx<'_>) -> Vec<Signal> {
        Vec::new()
    }
}
