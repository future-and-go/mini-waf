//! FR-010 fingerprint algorithms.
//!
//! Phase-04: real JA3 / JA4 / Akamai HTTP-2 implementations and a registry
//! that assembles an [`FpKey`](crate::device_fp::FpKey) from a
//! [`RawCapture`](crate::device_fp::capture::RawCapture).

pub mod fingerprint_trait;
pub mod h2_akamai;
pub mod ja3;
pub mod ja4;

pub use fingerprint_trait::FingerprintProvider;
pub use h2_akamai::{H2_AKAMAI_VERSION, H2AkamaiFingerprint};
pub use ja3::{JA3_VERSION, Ja3Fingerprint};
pub use ja4::{JA4_VERSION, Ja4Fingerprint};

use crate::device_fp::capture::RawCapture;
use crate::device_fp::types::FpKey;

/// Registry of the three fingerprint algorithms. Owns one instance of each
/// provider; `assemble()` runs all three against a single capture and
/// collects whichever produced a value into an [`FpKey`].
///
/// Kept separate from the signal-provider [`crate::device_fp::ProviderRegistry`]
/// because fingerprint hashes are computed once per connection (cached on
/// `ConnCtx`), while signal providers run per request.
pub struct FingerprintRegistry {
    ja3: Ja3Fingerprint,
    ja4: Ja4Fingerprint,
    h2: H2AkamaiFingerprint,
}

impl Default for FingerprintRegistry {
    fn default() -> Self {
        Self {
            ja3: Ja3Fingerprint,
            ja4: Ja4Fingerprint,
            h2: H2AkamaiFingerprint,
        }
    }
}

impl FingerprintRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute every fingerprint for `raw` and assemble into [`FpKey`].
    /// Providers that lack input bytes return `None` — those slots remain
    /// empty in the key (e.g. plaintext request → no JA3/JA4).
    #[must_use]
    pub fn assemble(&self, raw: &RawCapture) -> FpKey {
        FpKey {
            ja3: self.ja3.compute(raw),
            ja4: self.ja4.compute(raw),
            h2_akamai: self.h2.compute(raw),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_fp::capture::{H2Capture, ParsedClientHello};

    #[test]
    fn empty_capture_yields_empty_key() {
        let reg = FingerprintRegistry::new();
        let key = reg.assemble(&RawCapture::default());
        assert!(key.is_empty());
    }

    #[test]
    fn tls_only_capture_populates_ja3_and_ja4() {
        let reg = FingerprintRegistry::new();
        let raw = RawCapture {
            tls: Some(ParsedClientHello {
                legacy_version: 0x0303,
                cipher_suites: vec![0x1301, 0x1302],
                extensions: vec![0, 23],
                supported_groups: vec![29],
                sni: Some("a.test".into()),
                alpn: vec!["h2".into()],
                ..Default::default()
            }),
            h2: H2Capture::default(),
        };
        let key = reg.assemble(&raw);
        assert!(key.ja3.is_some());
        assert!(key.ja4.is_some());
        assert!(key.h2_akamai.is_none());
    }

    #[test]
    fn h2_only_capture_populates_h2_akamai() {
        let reg = FingerprintRegistry::new();
        let raw = RawCapture {
            tls: None,
            h2: H2Capture {
                settings: vec![(1, 65536)],
                ..Default::default()
            },
        };
        let key = reg.assemble(&raw);
        assert!(key.ja3.is_none());
        assert!(key.h2_akamai.is_some());
    }
}
