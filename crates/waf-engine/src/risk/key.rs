//! FR-025 risk identity key types.
//!
//! `RiskKey` bundles the three identity axes (IP, fingerprint hash, session)
//! used to look up / update risk state. Not all axes are always present —
//! a request without a device fingerprint still has IP; a request without
//! a session cookie still has IP + fingerprint.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::device_fp::types::FpKey;

/// Opaque session identifier extracted from a session cookie.
///
/// Stored as raw bytes (typically 16–32 bytes from a signed token). The
/// gateway extracts this from the configured session cookie name; if absent,
/// `RiskKey::session` is `None`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub Vec<u8>);

impl SessionId {
    #[must_use]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Composite identity key for risk-state lookup.
///
/// At least one leg (IP) is always present. Fingerprint hash and session may
/// be `None` depending on request context.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct RiskKey {
    pub ip: Option<IpAddr>,
    pub fp_hash: Option<u64>,
    pub session: Option<SessionId>,
}

impl RiskKey {
    /// Build a key with only the IP axis populated.
    #[must_use]
    pub const fn from_ip(ip: IpAddr) -> Self {
        Self {
            ip: Some(ip),
            fp_hash: None,
            session: None,
        }
    }

    /// Derive a truncated 64-bit hash from an `FpKey`.
    ///
    /// Uses SHA-256 and takes the first 8 bytes as a `u64`. Returns `None`
    /// if the `FpKey` is empty (no fingerprint algorithms produced values).
    #[must_use]
    pub fn hash_fp_key(fp: &FpKey) -> Option<u64> {
        if fp.is_empty() {
            return None;
        }
        let mut hasher = Sha256::new();
        if let Some(ref ja3) = fp.ja3 {
            hasher.update(b"ja3:");
            hasher.update(ja3.as_str().as_bytes());
        }
        if let Some(ref ja4) = fp.ja4 {
            hasher.update(b"ja4:");
            hasher.update(ja4.as_str().as_bytes());
        }
        if let Some(ref h2) = fp.h2_akamai {
            hasher.update(b"h2:");
            hasher.update(h2.as_str().as_bytes());
        }
        let digest = hasher.finalize();
        let bytes: [u8; 8] = digest.get(..8).and_then(|s| s.try_into().ok()).unwrap_or_default();
        Some(u64::from_le_bytes(bytes))
    }

    /// True if no identity axis is populated — caller should skip store ops.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.ip.is_none() && self.fp_hash.is_none() && self.session.is_none()
    }

    /// Count of populated axes (1–3).
    #[must_use]
    pub fn axis_count(&self) -> usize {
        usize::from(self.ip.is_some()) + usize::from(self.fp_hash.is_some()) + usize::from(self.session.is_some())
    }

    /// Derive a canonical owner ID string for challenge credit binding.
    ///
    /// Priority: session (strongest binding) > fingerprint > IP.
    /// Returns a deterministic string that uniquely identifies this actor.
    #[must_use]
    pub fn owner_id(&self) -> String {
        // Prefer session (strongest identity binding)
        if let Some(ref session) = self.session {
            return format!("sid:{}", hex::encode(session.as_bytes()));
        }
        // Fall back to fingerprint hash
        if let Some(fp_hash) = self.fp_hash {
            return format!("fp:{fp_hash:016x}");
        }
        // Last resort: IP
        if let Some(ip) = self.ip {
            return format!("ip:{ip}");
        }
        // Should not happen if is_empty() was checked
        "unknown".to_string()
    }
}

#[cfg(test)]
#[allow(clippy::unreadable_literal)]
mod tests {
    use super::*;
    use crate::device_fp::types::FingerprintValue;
    use std::net::Ipv4Addr;

    #[test]
    fn empty_fp_key_returns_none() {
        let fp = FpKey::default();
        assert!(RiskKey::hash_fp_key(&fp).is_none());
    }

    #[test]
    fn non_empty_fp_key_returns_hash() {
        let fp = FpKey {
            ja3: Some(FingerprintValue::new("test-ja3")),
            ja4: None,
            h2_akamai: None,
        };
        let hash = RiskKey::hash_fp_key(&fp);
        assert!(hash.is_some());
        assert_ne!(hash.unwrap(), 0);
    }

    #[test]
    fn from_ip_populates_ip_only() {
        let key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(key.ip.is_some());
        assert!(key.fp_hash.is_none());
        assert!(key.session.is_none());
        assert_eq!(key.axis_count(), 1);
    }

    #[test]
    fn empty_key_is_empty() {
        let key = RiskKey::default();
        assert!(key.is_empty());
        assert_eq!(key.axis_count(), 0);
    }

    #[test]
    fn axis_count_combinations() {
        let mut k = RiskKey::default();
        assert_eq!(k.axis_count(), 0);

        k.ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(k.axis_count(), 1);

        k.fp_hash = Some(0xAA);
        assert_eq!(k.axis_count(), 2);

        k.session = Some(SessionId::new(vec![1, 2, 3]));
        assert_eq!(k.axis_count(), 3);
        assert!(!k.is_empty());
    }

    #[test]
    fn owner_id_prefers_session_over_fp_and_ip() {
        let key = RiskKey {
            ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            fp_hash: Some(0x1234_5678_ABCD_EF00),
            session: Some(SessionId::new(vec![0xDE, 0xAD])),
        };
        let id = key.owner_id();
        assert!(id.starts_with("sid:"), "session takes priority: {id}");
        assert!(id.contains("dead"));
    }

    #[test]
    fn owner_id_falls_back_to_fp_when_no_session() {
        let key = RiskKey {
            ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            fp_hash: Some(0xCAFEF00D),
            session: None,
        };
        let id = key.owner_id();
        assert!(id.starts_with("fp:"), "{id}");
        assot_contains(&id, "00000000cafef00d");
    }

    #[test]
    fn owner_id_falls_back_to_ip_when_no_session_no_fp() {
        let key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)));
        let id = key.owner_id();
        assert_eq!(id, "ip:8.8.4.4");
    }

    #[test]
    fn owner_id_handles_fully_empty_key() {
        let key = RiskKey::default();
        assert_eq!(key.owner_id(), "unknown");
    }

    #[test]
    fn hash_fp_key_changes_with_fields() {
        let fp_a = FpKey {
            ja3: Some(FingerprintValue::new("v1")),
            ja4: None,
            h2_akamai: None,
        };
        let fp_b = FpKey {
            ja3: Some(FingerprintValue::new("v2")),
            ja4: None,
            h2_akamai: None,
        };
        let fp_full = FpKey {
            ja3: Some(FingerprintValue::new("v1")),
            ja4: Some(FingerprintValue::new("ja4-x")),
            h2_akamai: Some(FingerprintValue::new("h2-y")),
        };
        let h_a = RiskKey::hash_fp_key(&fp_a).unwrap();
        let h_b = RiskKey::hash_fp_key(&fp_b).unwrap();
        let h_full = RiskKey::hash_fp_key(&fp_full).unwrap();
        assert_ne!(h_a, h_b);
        assert_ne!(h_a, h_full);
    }

    fn assot_contains(haystack: &str, needle: &str) {
        assert!(haystack.contains(needle), "{haystack} should contain {needle}");
    }
}
