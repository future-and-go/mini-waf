//! JA4 fingerprint — `FoxIO` spec (TLS variant `JA4` only; `JA4S`/`JA4H`/`JA4X` are future).
//!
//! Output: `<JA4_a>_<JA4_b>_<JA4_c>`
//!
//! - `JA4_a` (10 chars): `<proto><tls_ver><sni><nciphers><nexts><alpn>`
//!   - proto: `t` (TCP) or `q` (`QUIC`); we always emit `t` — phase-03 does not capture `QUIC`
//!   - `tls_ver`: 2 chars from negotiated/legacy version (`13`/`12`/`11`/`10`/`s3`/`s2`/`00`)
//!   - sni: `d` if SNI present, else `i`
//!   - nciphers: 2-digit decimal count of non-GREASE cipher suites (clamped to 99)
//!   - nexts: 2-digit decimal count of non-GREASE extensions (clamped to 99)
//!   - alpn: first + last char of first ALPN value; `00` when absent;
//!     non-printable bytes are replaced with `9` per spec
//! - `JA4_b` (12 hex): first 12 chars of `sha256` over sorted, lowercase, 4-digit-hex
//!   cipher list, comma-joined (GREASE removed). Empty cipher list → 12 zeros.
//! - `JA4_c` (12 hex): first 12 chars of `sha256` over
//!   `<sorted exts excluding SNI(0x0000) and ALPN(0x0010)>_<sig_algs in original order>`.
//!   Sig algs missing → trailing underscore is dropped per spec.
//!
//! Version pinned to `FoxIO` spec date `2024-01`. Bump [`JA4_VERSION`] on spec changes.

use sha2::{Digest, Sha256};

use crate::device_fp::capture::RawCapture;
use crate::device_fp::fingerprint::FingerprintProvider;
use crate::device_fp::fingerprint::ja3::is_grease;
use crate::device_fp::types::FingerprintValue;

pub const JA4_VERSION: &str = "2024-01";
const HASH_LEN: usize = 12;

#[derive(Debug, Default)]
pub struct Ja4Fingerprint;

impl FingerprintProvider for Ja4Fingerprint {
    fn name(&self) -> &'static str {
        "ja4"
    }

    fn compute(&self, raw: &RawCapture) -> Option<FingerprintValue> {
        let tls = raw.tls.as_ref()?;
        let a = ja4_a(tls);
        let b = ja4_b(&tls.cipher_suites);
        let c = ja4_c(&tls.extensions, &tls.signature_algorithms);
        Some(FingerprintValue::new(format!("{a}_{b}_{c}")))
    }
}

fn ja4_a(tls: &crate::device_fp::capture::ParsedClientHello) -> String {
    let proto = 't';
    let tls_ver = tls_version_label(tls.legacy_version);
    let sni = if tls.sni.is_some() { 'd' } else { 'i' };
    let nciphers = clamp_count(tls.cipher_suites.iter().copied().filter(|v| !is_grease(*v)).count());
    let nexts = clamp_count(tls.extensions.iter().copied().filter(|v| !is_grease(*v)).count());
    let alpn = alpn_pair(tls.alpn.first().map(String::as_str));
    format!("{proto}{tls_ver}{sni}{nciphers:02}{nexts:02}{alpn}")
}

fn ja4_b(ciphers: &[u16]) -> String {
    let mut filtered: Vec<u16> = ciphers.iter().copied().filter(|v| !is_grease(*v)).collect();
    filtered.sort_unstable();
    let joined = hex_csv(&filtered);
    sha256_truncated(&joined)
}

fn ja4_c(extensions: &[u16], sig_algs: &[u16]) -> String {
    // Per spec: exclude SNI (0x0000) and ALPN (0x0010) from the sorted ext list.
    let mut exts: Vec<u16> = extensions
        .iter()
        .copied()
        .filter(|v| !is_grease(*v) && *v != 0x0000 && *v != 0x0010)
        .collect();
    exts.sort_unstable();
    let exts_csv = hex_csv(&exts);
    // Sig algs preserve original order, only GREASE removed.
    let sig_csv = hex_csv_keep_order(sig_algs);
    let payload = if sig_csv.is_empty() {
        exts_csv
    } else {
        format!("{exts_csv}_{sig_csv}")
    };
    sha256_truncated(&payload)
}

const fn tls_version_label(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        _ => "00",
    }
}

const fn clamp_count(n: usize) -> usize {
    if n > 99 { 99 } else { n }
}

fn alpn_pair(alpn: Option<&str>) -> String {
    let Some(s) = alpn else {
        return "00".to_string();
    };
    let bytes = s.as_bytes();
    let (Some(&first_byte), Some(&last_byte)) = (bytes.first(), bytes.last()) else {
        return "00".to_string();
    };
    let mut out = String::with_capacity(2);
    out.push(sanitize_alpn_byte(first_byte));
    out.push(sanitize_alpn_byte(last_byte));
    out
}

const fn sanitize_alpn_byte(b: u8) -> char {
    // Spec: non-alphanumeric bytes are replaced with '9'.
    if b.is_ascii_alphanumeric() {
        b as char
    } else {
        '9'
    }
}

fn hex_csv(values: &[u16]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(&mut out, "{v:04x}");
    }
    out
}

fn hex_csv_keep_order(values: &[u16]) -> String {
    let filtered: Vec<u16> = values.iter().copied().filter(|v| !is_grease(*v)).collect();
    hex_csv(&filtered)
}

fn sha256_truncated(input: &str) -> String {
    if input.is_empty() {
        // Per FoxIO ref: empty input → 12 zeros (not the sha256 of empty string).
        return "000000000000".to_string();
    }
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    let mut s = hex::encode(digest);
    s.truncate(HASH_LEN);
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_fp::capture::ParsedClientHello;

    fn raw(tls: ParsedClientHello) -> RawCapture {
        RawCapture {
            tls: Some(tls),
            h2: crate::device_fp::capture::H2Capture::default(),
        }
    }

    #[test]
    fn no_tls_returns_none() {
        assert!(Ja4Fingerprint.compute(&RawCapture::default()).is_none());
    }

    #[test]
    fn ja4_a_layout() {
        let r = raw(ParsedClientHello {
            legacy_version: 0x0303,
            cipher_suites: vec![0x1301, 0x1302, 0x0A0A], // GREASE dropped
            extensions: vec![0, 16, 23, 0x1A1A],         // GREASE dropped, count includes SNI/ALPN
            sni: Some("example.com".into()),
            alpn: vec!["h2".into()],
            ..Default::default()
        });
        let fp = Ja4Fingerprint.compute(&r).unwrap();
        let parts: Vec<&str> = fp.as_str().split('_').collect();
        assert_eq!(parts.len(), 3);
        // proto(t) + ver(12) + sni(d) + nciphers(02) + nexts(03) + alpn(h2)
        assert_eq!(parts.first().copied(), Some("t12d0203h2"));
        assert_eq!(parts.first().map(|s| s.len()), Some(10));
        assert_eq!(parts.get(1).map(|s| s.len()), Some(12));
        assert_eq!(parts.get(2).map(|s| s.len()), Some(12));
    }

    #[test]
    fn ja4_b_sorts_and_strips_grease() {
        // Two captures differing only by cipher order + GREASE → identical b.
        let r1 = raw(ParsedClientHello {
            legacy_version: 0x0304,
            cipher_suites: vec![0x1302, 0x1301],
            ..Default::default()
        });
        let r2 = raw(ParsedClientHello {
            legacy_version: 0x0304,
            cipher_suites: vec![0x0A0A, 0x1301, 0x1302, 0x1A1A],
            ..Default::default()
        });
        let b1 = Ja4Fingerprint.compute(&r1).unwrap();
        let b2 = Ja4Fingerprint.compute(&r2).unwrap();
        let mid = |s: &str| s.split('_').nth(1).unwrap().to_string();
        assert_eq!(mid(b1.as_str()), mid(b2.as_str()));
    }

    #[test]
    fn ja4_c_excludes_sni_and_alpn_extensions() {
        // Extensions list { 0, 16, 23 } and { 23 } produce same JA4_c
        // because SNI(0) and ALPN(16) are excluded from the c-hash input.
        let r1 = raw(ParsedClientHello {
            legacy_version: 0x0304,
            extensions: vec![0, 16, 23],
            ..Default::default()
        });
        let r2 = raw(ParsedClientHello {
            legacy_version: 0x0304,
            extensions: vec![23],
            ..Default::default()
        });
        let last = |s: &str| s.split('_').nth(2).unwrap().to_string();
        let c1 = Ja4Fingerprint.compute(&r1).unwrap();
        let c2 = Ja4Fingerprint.compute(&r2).unwrap();
        assert_eq!(last(c1.as_str()), last(c2.as_str()));
    }

    #[test]
    fn alpn_absent_uses_zero_zero() {
        let r = raw(ParsedClientHello {
            legacy_version: 0x0304,
            ..Default::default()
        });
        let fp = Ja4Fingerprint.compute(&r).unwrap();
        let a = fp.as_str().split('_').next().unwrap();
        assert!(a.ends_with("00"));
    }

    #[test]
    fn alpn_non_alnum_replaced_with_9() {
        assert_eq!(alpn_pair(Some("\x01\x02")), "99");
        assert_eq!(alpn_pair(Some("h2")), "h2");
    }

    #[test]
    fn count_clamped_to_99() {
        let many: Vec<u16> = (1..=200).collect();
        let r = raw(ParsedClientHello {
            legacy_version: 0x0304,
            cipher_suites: many,
            ..Default::default()
        });
        let fp = Ja4Fingerprint.compute(&r).unwrap();
        let a = fp.as_str().split('_').next().unwrap();
        // proto(1) + ver(2) + sni(1) + nciphers(2 = "99")
        assert_eq!(&a[4..6], "99");
    }

    #[test]
    fn deterministic() {
        let r = raw(ParsedClientHello {
            legacy_version: 0x0304,
            cipher_suites: vec![0x1301, 0x1302],
            extensions: vec![0, 23, 16],
            supported_groups: vec![29, 23],
            signature_algorithms: vec![0x0403, 0x0804],
            sni: Some("a.test".into()),
            alpn: vec!["h2".into()],
        });
        assert_eq!(Ja4Fingerprint.compute(&r), Ja4Fingerprint.compute(&r));
    }

    #[test]
    fn empty_cipher_list_yields_zero_b() {
        assert_eq!(ja4_b(&[]), "000000000000");
    }

    #[test]
    fn version_label_table() {
        assert_eq!(tls_version_label(0x0304), "13");
        assert_eq!(tls_version_label(0x0303), "12");
        assert_eq!(tls_version_label(0x0302), "11");
        assert_eq!(tls_version_label(0x0301), "10");
        assert_eq!(tls_version_label(0x0300), "s3");
        assert_eq!(tls_version_label(0x0002), "s2");
        assert_eq!(tls_version_label(0xFFFF), "00");
    }
}
