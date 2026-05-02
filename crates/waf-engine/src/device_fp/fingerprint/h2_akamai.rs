//! HTTP/2 Akamai fingerprint — phase-02 stub. Real impl in phase-04.

use crate::device_fp::capture::RawCapture;
use crate::device_fp::fingerprint::FingerprintProvider;
use crate::device_fp::types::FingerprintValue;

#[derive(Debug, Default)]
pub struct H2AkamaiFingerprint;

impl FingerprintProvider for H2AkamaiFingerprint {
    fn name(&self) -> &'static str {
        "h2_akamai"
    }

    fn compute(&self, _raw: &RawCapture) -> Option<FingerprintValue> {
        None
    }
}
