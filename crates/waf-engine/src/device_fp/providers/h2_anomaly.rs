//! HTTP/2 frame sequence anomaly — phase-02 stub.

use crate::device_fp::providers::SignalProvider;
use crate::device_fp::signal::Signal;
use crate::device_fp::types::DeviceCtx;

#[derive(Debug, Default)]
pub struct H2AnomalyProvider;

impl SignalProvider for H2AnomalyProvider {
    fn name(&self) -> &'static str {
        "h2_anomaly"
    }
    fn evaluate(&self, _ctx: &DeviceCtx<'_>) -> Vec<Signal> {
        Vec::new()
    }
}
