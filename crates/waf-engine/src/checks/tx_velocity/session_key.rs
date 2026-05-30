//! FR-012 phase-01 — session-key extraction.
//!
//! Identity preference order:
//!   1. Session cookie value (configured by `session_cookie`)
//!   2. Device fingerprint key fallback (`FpKey` from FR-010)
//!
//! Returns `None` when neither source yields an identifier — the recorder
//! skips tracking for those requests rather than bucketing them all into
//! one super-key.

use std::net::IpAddr;

use waf_common::RequestCtx;

use crate::device_fp::types::FpKey;

/// Identity tied to a tracked actor. Cookie values are kept as opaque
/// `String` so we never have to log or expose them — the value lives only
/// inside the `DashMap` key.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum SessionIdent {
    Cookie(String),
    /// Fingerprint scoped by peer IP to prevent CDN cohort poisoning (shared
    /// JA3 behind `CloudFront` bucketing unrelated clients together).
    Fingerprint {
        fp: FpKey,
        ip: IpAddr,
    },
}

/// Composite key the recorder buckets events under. Host scoping prevents
/// cross-tenant collision when the same cookie name is reused.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SessionKey {
    pub host: String,
    pub ident: SessionIdent,
}

/// Extract the per-request session key. Cookie wins; otherwise fall back
/// to fingerprint scoped by peer IP. `fp` is `None` when device-fp is
/// disabled or the observation produced no fingerprint values.
#[must_use]
pub fn extract_session_key(
    ctx: &RequestCtx,
    cookie_name: &str,
    fp: Option<&FpKey>,
    peer_ip: IpAddr,
) -> Option<SessionKey> {
    if let Some(value) = ctx.cookies.get(cookie_name)
        && !value.is_empty()
    {
        return Some(SessionKey {
            host: ctx.host.clone(),
            ident: SessionIdent::Cookie(value.clone()),
        });
    }
    if let Some(key) = fp
        && !key.is_empty()
    {
        return Some(SessionKey {
            host: ctx.host.clone(),
            ident: SessionIdent::Fingerprint {
                fp: key.clone(),
                ip: peer_ip,
            },
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_fp::types::FingerprintValue;
    use std::collections::HashMap;

    const PEER: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

    fn ctx_with_cookies(cookies: HashMap<String, String>) -> RequestCtx {
        RequestCtx {
            host: "h.example".to_string(),
            cookies,
            ..Default::default()
        }
    }

    fn fp(tag: &str) -> FpKey {
        FpKey {
            ja3: Some(FingerprintValue::new(tag)),
            ja4: None,
            h2_akamai: None,
        }
    }

    #[test]
    fn cookie_wins_over_fingerprint() {
        let mut cookies = HashMap::new();
        cookies.insert("SID".to_string(), "abc123".to_string());
        let ctx = ctx_with_cookies(cookies);
        let key = extract_session_key(&ctx, "SID", Some(&fp("ja3-x")), PEER).expect("key");
        assert_eq!(key.host, "h.example");
        assert!(matches!(key.ident, SessionIdent::Cookie(ref v) if v == "abc123"));
    }

    #[test]
    fn empty_cookie_value_falls_through_to_fp() {
        let mut cookies = HashMap::new();
        cookies.insert("SID".to_string(), String::new());
        let ctx = ctx_with_cookies(cookies);
        let key = extract_session_key(&ctx, "SID", Some(&fp("ja3-x")), PEER).expect("key");
        assert!(matches!(key.ident, SessionIdent::Fingerprint { .. }));
    }

    #[test]
    fn fingerprint_fallback_used_when_cookie_missing() {
        let ctx = ctx_with_cookies(HashMap::new());
        let key = extract_session_key(&ctx, "SID", Some(&fp("ja3-y")), PEER).expect("key");
        assert!(matches!(key.ident, SessionIdent::Fingerprint { .. }));
    }

    #[test]
    fn fingerprint_includes_peer_ip() {
        let ctx = ctx_with_cookies(HashMap::new());
        let peer = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let key = extract_session_key(&ctx, "SID", Some(&fp("ja3-z")), peer).expect("key");
        match &key.ident {
            SessionIdent::Fingerprint { ip, .. } => assert_eq!(*ip, peer),
            SessionIdent::Cookie(_) => panic!("expected Fingerprint variant"),
        }
    }

    #[test]
    fn empty_fingerprint_skipped() {
        let ctx = ctx_with_cookies(HashMap::new());
        let empty_fp = FpKey::default();
        assert!(extract_session_key(&ctx, "SID", Some(&empty_fp), PEER).is_none());
    }

    #[test]
    fn no_cookie_no_fp_returns_none() {
        let ctx = ctx_with_cookies(HashMap::new());
        assert!(extract_session_key(&ctx, "SID", None, PEER).is_none());
    }
}
