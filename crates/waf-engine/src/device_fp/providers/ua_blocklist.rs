//! User-Agent matched operator blocklist pattern — phase-02 stub.

use crate::device_fp::providers::SignalProvider;
use crate::device_fp::signal::Signal;
use crate::device_fp::types::DeviceCtx;

#[derive(Debug, Default)]
pub struct UaBlocklistProvider;

impl SignalProvider for UaBlocklistProvider {
    fn name(&self) -> &'static str {
        "ua_blocklist"
    }
    fn evaluate(&self, _ctx: &DeviceCtx<'_>) -> Vec<Signal> {
        Vec::new()
    }
}
