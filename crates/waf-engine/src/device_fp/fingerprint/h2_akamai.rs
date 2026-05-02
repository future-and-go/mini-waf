//! HTTP/2 Akamai fingerprint — Akamai 2017 white-paper format.
//!
//! Canonical string: `S[settings]|[window]|[priorities]|[pseudo_order]`
//! - `settings`: SETTINGS payload as `id:value` pairs in arrival order, joined `;`
//!   (order matters per spec — clients send a stable order)
//! - `window`: connection-level `WINDOW_UPDATE` increment for stream 0; `00` if absent
//! - `priorities`: PRIORITY frames as `streamId:exclusive:depends_on:weight`,
//!   joined `,` in arrival order; `0` if no PRIORITY frames seen
//! - `pseudo_order`: pseudo-header order on stream 1's HEADERS frame
//!   (e.g. `m,a,s,p` for `:method`, `:authority`, `:scheme`, `:path`)
//!
//! We publish both the canonical string and a 12-hex truncated SHA-256 for
//! storage compactness. The canonical form is preserved as the published
//! `value` so operators can audit the breakdown.
//!
//! Pinned to spec format `2017-akamai-v1`. Bump on schema change.

use sha2::{Digest, Sha256};

use crate::device_fp::capture::{H2Capture, RawCapture};
use crate::device_fp::fingerprint::FingerprintProvider;
use crate::device_fp::types::FingerprintValue;

pub const H2_AKAMAI_VERSION: &str = "2017-akamai-v1";

#[derive(Debug, Default)]
pub struct H2AkamaiFingerprint;

impl H2AkamaiFingerprint {
    /// Build the canonical Akamai h2 string. Returns `None` when capture is
    /// effectively empty (no SETTINGS, no priorities, no pseudo order).
    #[must_use]
    pub fn canonical(h2: &H2Capture) -> Option<String> {
        if h2.settings.is_empty()
            && h2.window_updates.is_empty()
            && h2.priority.is_empty()
            && h2.pseudo_header_order.is_none()
        {
            return None;
        }

        let settings = encode_settings(&h2.settings);
        let window = encode_window(&h2.window_updates);
        let priorities = encode_priorities(&h2.priority);
        let pseudo = encode_pseudo(h2.pseudo_header_order.as_deref());
        Some(format!("{settings}|{window}|{priorities}|{pseudo}"))
    }
}

impl FingerprintProvider for H2AkamaiFingerprint {
    fn name(&self) -> &'static str {
        "h2_akamai"
    }

    fn compute(&self, raw: &RawCapture) -> Option<FingerprintValue> {
        let canonical = Self::canonical(&raw.h2)?;
        // Published value: `<hash>:<canonical>` so downstream rules can match
        // either the truncated hash or the raw breakdown.
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        let mut hash = hex::encode(hasher.finalize());
        hash.truncate(12);
        Some(FingerprintValue::new(format!("{hash}:{canonical}")))
    }
}

fn encode_settings(settings: &[(u16, u32)]) -> String {
    let parts: Vec<String> = settings.iter().map(|(id, val)| format!("{id}:{val}")).collect();
    parts.join(";")
}

fn encode_window(updates: &[(u32, u32)]) -> String {
    // Akamai spec uses the connection-level (stream 0) WINDOW_UPDATE.
    updates
        .iter()
        .find(|(stream, _)| *stream == 0)
        .map_or_else(|| "00".to_string(), |(_, inc)| inc.to_string())
}

fn encode_priorities(priorities: &[crate::device_fp::capture::PriorityFrame]) -> String {
    if priorities.is_empty() {
        return "0".to_string();
    }
    let parts: Vec<String> = priorities
        .iter()
        .map(|p| {
            format!(
                "{}:{}:{}:{}",
                p.stream_id,
                u8::from(p.exclusive),
                p.depends_on,
                p.weight
            )
        })
        .collect();
    parts.join(",")
}

fn encode_pseudo(order: Option<&[String]>) -> String {
    let Some(headers) = order else {
        return "0".to_string();
    };
    if headers.is_empty() {
        return "0".to_string();
    }
    headers
        .iter()
        .map(|h| pseudo_letter(h.as_str()))
        .collect::<Vec<_>>()
        .join(",")
}

fn pseudo_letter(name: &str) -> &'static str {
    // Akamai abbreviates the four standard request pseudo-headers.
    match name {
        ":method" => "m",
        ":authority" => "a",
        ":scheme" => "s",
        ":path" => "p",
        ":status" => "st",
        _ => "x",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_fp::capture::PriorityFrame;

    fn raw(h2: H2Capture) -> RawCapture {
        RawCapture { tls: None, h2 }
    }

    #[test]
    fn empty_capture_returns_none() {
        assert!(H2AkamaiFingerprint.compute(&RawCapture::default()).is_none());
    }

    #[test]
    fn canonical_format_matches_paper() {
        let r = raw(H2Capture {
            settings: vec![(1, 65_536), (3, 1000), (4, 6_291_456), (6, 262_144)],
            window_updates: vec![(0, 15_663_105)],
            priority: vec![PriorityFrame {
                stream_id: 3,
                depends_on: 0,
                weight: 201,
                exclusive: true,
            }],
            pseudo_header_order: Some(vec![
                ":method".into(),
                ":authority".into(),
                ":scheme".into(),
                ":path".into(),
            ]),
        });
        let s = H2AkamaiFingerprint::canonical(&r.h2).unwrap();
        assert_eq!(s, "1:65536;3:1000;4:6291456;6:262144|15663105|3:1:0:201|m,a,s,p");
    }

    #[test]
    fn settings_order_matters() {
        let a = H2AkamaiFingerprint::canonical(&H2Capture {
            settings: vec![(1, 100), (3, 200)],
            ..Default::default()
        })
        .unwrap();
        let b = H2AkamaiFingerprint::canonical(&H2Capture {
            settings: vec![(3, 200), (1, 100)],
            ..Default::default()
        })
        .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn missing_window_uses_double_zero() {
        let s = H2AkamaiFingerprint::canonical(&H2Capture {
            settings: vec![(1, 100)],
            ..Default::default()
        })
        .unwrap();
        assert!(s.contains("|00|"));
    }

    #[test]
    fn no_priority_emits_zero() {
        let s = H2AkamaiFingerprint::canonical(&H2Capture {
            settings: vec![(1, 100)],
            ..Default::default()
        })
        .unwrap();
        let parts: Vec<&str> = s.split('|').collect();
        assert_eq!(parts.get(2).copied(), Some("0"));
    }

    #[test]
    fn fingerprint_publishes_hash_colon_canonical() {
        let r = raw(H2Capture {
            settings: vec![(1, 100)],
            ..Default::default()
        });
        let v = H2AkamaiFingerprint.compute(&r).unwrap();
        let s = v.as_str();
        let (hash, rest) = s.split_once(':').unwrap();
        assert_eq!(hash.len(), 12);
        assert!(rest.contains("|00|0|0"));
    }

    #[test]
    fn deterministic() {
        let r = raw(H2Capture {
            settings: vec![(1, 100), (3, 200)],
            window_updates: vec![(0, 1024)],
            priority: vec![PriorityFrame {
                stream_id: 1,
                depends_on: 0,
                weight: 16,
                exclusive: false,
            }],
            pseudo_header_order: Some(vec![":method".into(), ":path".into()]),
        });
        assert_eq!(H2AkamaiFingerprint.compute(&r), H2AkamaiFingerprint.compute(&r));
    }

    #[test]
    fn unknown_pseudo_marked_x() {
        let s = H2AkamaiFingerprint::canonical(&H2Capture {
            settings: vec![(1, 100)],
            pseudo_header_order: Some(vec![":method".into(), ":custom".into()]),
            ..Default::default()
        })
        .unwrap();
        assert!(s.ends_with("|m,x"));
    }
}
