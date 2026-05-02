//! Trait every fingerprint algorithm implements.
//!
//! `compute()` returns `None` when the raw capture lacks the bytes needed
//! (e.g. plaintext request → no `ClientHello` → no JA3). The assembler
//! collects whichever values are `Some` into [`crate::device_fp::FpKey`].

use crate::device_fp::capture::RawCapture;
use crate::device_fp::types::FingerprintValue;

pub trait FingerprintProvider: Send + Sync {
    /// Stable short name (used as the key in metrics labels).
    fn name(&self) -> &'static str;

    /// Compute the fingerprint from a connection's raw capture.
    fn compute(&self, raw: &RawCapture) -> Option<FingerprintValue>;
}
