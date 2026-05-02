//! Same fingerprint observed across multiple IPs — phase-02 stub.

use crate::device_fp::providers::SignalProvider;
use crate::device_fp::signal::Signal;
use crate::device_fp::types::DeviceCtx;

#[derive(Debug, Default)]
pub struct IpHoppingProvider;

impl SignalProvider for IpHoppingProvider {
    fn name(&self) -> &'static str {
        "ip_hopping"
    }
    fn evaluate(&self, _ctx: &DeviceCtx<'_>) -> Vec<Signal> {
        Vec::new()
    }
}
