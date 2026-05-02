//! JA4 fingerprint — phase-02 stub. Real impl in phase-04.

use crate::device_fp::capture::RawCapture;
use crate::device_fp::fingerprint::FingerprintProvider;
use crate::device_fp::types::FingerprintValue;

#[derive(Debug, Default)]
pub struct Ja4Fingerprint;

impl FingerprintProvider for Ja4Fingerprint {
    fn name(&self) -> &'static str {
        "ja4"
    }

    fn compute(&self, _raw: &RawCapture) -> Option<FingerprintValue> {
        None
    }
}
