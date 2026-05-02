//! JA3 fingerprint — Salesforce spec.
//!
//! Format: `SSLVersion,Cipher,Extension,EllipticCurve,EllipticCurvePointFormat`
//! - fields are decimal cipher/ext/group IDs joined by `-`
//! - GREASE values (RFC 8701) stripped from cipher/extension/group lists
//! - MD5 of the canonical string is the published JA3 hash
//!
//! `point_formats` capture is not parsed yet (phase-03 didn't extract ext 11),
//! so we always emit it as empty — this matches the JA3 string emitted by
//! some implementations when the extension is absent and is documented.

use md5::{Digest, Md5};

use crate::device_fp::capture::RawCapture;
use crate::device_fp::fingerprint::FingerprintProvider;
use crate::device_fp::types::FingerprintValue;

pub const JA3_VERSION: &str = "v1";

#[derive(Debug, Default)]
pub struct Ja3Fingerprint;

impl Ja3Fingerprint {
    /// Build the canonical JA3 string (pre-hash). Public for golden tests.
    #[must_use]
    pub fn canonical(raw: &RawCapture) -> Option<String> {
        let tls = raw.tls.as_ref()?;
        let ciphers = join_filtered(&tls.cipher_suites);
        let exts = join_filtered(&tls.extensions);
        let groups = join_filtered(&tls.supported_groups);
        // point_formats not captured in phase-03 — emit empty field.
        let point_formats = String::new();
        Some(format!(
            "{},{},{},{},{}",
            tls.legacy_version, ciphers, exts, groups, point_formats
        ))
    }
}

impl FingerprintProvider for Ja3Fingerprint {
    fn name(&self) -> &'static str {
        "ja3"
    }

    fn compute(&self, raw: &RawCapture) -> Option<FingerprintValue> {
        let canonical = Self::canonical(raw)?;
        let mut hasher = Md5::new();
        hasher.update(canonical.as_bytes());
        let digest = hasher.finalize();
        Some(FingerprintValue::new(hex::encode(digest)))
    }
}

/// Strip GREASE values (RFC 8701: `0x?A?A` form) and join with `-`.
fn join_filtered(values: &[u16]) -> String {
    let mut first = true;
    let mut out = String::new();
    for v in values.iter().copied().filter(|v| !is_grease(*v)) {
        if !first {
            out.push('-');
        }
        out.push_str(&v.to_string());
        first = false;
    }
    out
}

/// RFC 8701 GREASE values: high & low byte both `0x?A`, equal nibbles.
#[must_use]
pub const fn is_grease(v: u16) -> bool {
    let lo = (v & 0xFF) as u8;
    let hi = (v >> 8) as u8;
    hi == lo && (lo & 0x0F) == 0x0A
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_fp::capture::ParsedClientHello;

    fn capture(tls: ParsedClientHello) -> RawCapture {
        RawCapture {
            tls: Some(tls),
            h2: crate::device_fp::capture::H2Capture::default(),
        }
    }

    #[test]
    fn no_tls_returns_none() {
        let raw = RawCapture::default();
        assert!(Ja3Fingerprint.compute(&raw).is_none());
    }

    #[test]
    fn canonical_format_matches_spec() {
        let raw = capture(ParsedClientHello {
            legacy_version: 771,
            cipher_suites: vec![0x1301, 0x1302],
            extensions: vec![0, 23, 65281],
            supported_groups: vec![29, 23],
            ..Default::default()
        });
        let s = Ja3Fingerprint::canonical(&raw).unwrap();
        assert_eq!(s, "771,4865-4866,0-23-65281,29-23,");
    }

    #[test]
    fn grease_values_stripped() {
        // 0x0A0A and 0x1A1A are GREASE per RFC 8701.
        let raw = capture(ParsedClientHello {
            legacy_version: 771,
            cipher_suites: vec![0x0A0A, 0x1301, 0x1A1A],
            extensions: vec![0x0A0A, 0],
            supported_groups: vec![0x1A1A, 29],
            ..Default::default()
        });
        let s = Ja3Fingerprint::canonical(&raw).unwrap();
        assert_eq!(s, "771,4865,0,29,");
    }

    #[test]
    fn md5_is_deterministic() {
        let raw = capture(ParsedClientHello {
            legacy_version: 771,
            cipher_suites: vec![0x1301],
            extensions: vec![0],
            supported_groups: vec![29],
            ..Default::default()
        });
        let a = Ja3Fingerprint.compute(&raw).unwrap();
        let b = Ja3Fingerprint.compute(&raw).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.as_str().len(), 32); // md5 hex
    }

    #[test]
    fn is_grease_recognises_full_table() {
        // Per RFC 8701 the GREASE values are 0x0A0A, 0x1A1A, ..., 0xFAFA.
        for nibble in 0u8..=0xF {
            let byte: u8 = (nibble << 4) | 0x0A;
            let v: u16 = (u16::from(byte) << 8) | u16::from(byte);
            assert!(is_grease(v), "expected GREASE: {v:#06x}");
        }
        assert!(!is_grease(0x1301));
        assert!(!is_grease(0x0A0B)); // mismatched bytes
    }
}
