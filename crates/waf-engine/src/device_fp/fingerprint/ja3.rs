//! JA3 fingerprint — phase-02 stub. Real impl in phase-04.

use crate::device_fp::capture::RawCapture;
use crate::device_fp::fingerprint::FingerprintProvider;
use crate::device_fp::types::FingerprintValue;

#[derive(Debug, Default)]
pub struct Ja3Fingerprint;

impl FingerprintProvider for Ja3Fingerprint {
    fn name(&self) -> &'static str {
        "ja3"
    }

    fn compute(&self, _raw: &RawCapture) -> Option<FingerprintValue> {
        None
    }
}
