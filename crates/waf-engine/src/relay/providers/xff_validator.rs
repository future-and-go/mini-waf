//! FR-007 phase-02 — `XffValidator` provider.
//!
//! Emits `XffTooLong`, `XffMalformed`, `XffSpoofPrivate` based on the
//! cached `Derived` populated via `RelayCtx::populate_derived`.

use http::HeaderName;
use ipnet::IpNet;

use crate::relay::signal::{RelayCtx, Signal, SignalProvider};

pub struct XffValidator {
    headers: Vec<HeaderName>,
    trusted: Vec<IpNet>,
}

impl XffValidator {
    pub fn new(header_names: &[String], trusted: Vec<IpNet>) -> anyhow::Result<Self> {
        let mut headers = Vec::with_capacity(header_names.len());
        for n in header_names {
            let parsed =
                HeaderName::from_bytes(n.as_bytes()).map_err(|e| anyhow::anyhow!("invalid header name {n:?}: {e}"))?;
            headers.push(parsed);
        }
        Ok(Self { headers, trusted })
    }
}

impl SignalProvider for XffValidator {
    fn name(&self) -> &'static str {
        "xff_validator"
    }

    fn evaluate(&self, ctx: &RelayCtx<'_>) -> Vec<Signal> {
        let d = ctx.populate_derived(&self.headers, &self.trusted);
        let mut out = Vec::new();
        if d.parsed.too_long_bytes || d.parsed.too_long_count {
            out.push(Signal::XffTooLong);
        }
        if d.parsed.malformed {
            out.push(Signal::XffMalformed);
        }
        if d.spoof_private_mid_chain {
            out.push(Signal::XffSpoofPrivate);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::providers::parse::MAX_HEADER_BYTES;
    use http::{HeaderMap, HeaderValue};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Instant;

    fn names() -> Vec<String> {
        vec!["X-Forwarded-For".into()]
    }

    fn ctx(headers: &HeaderMap) -> RelayCtx<'_> {
        RelayCtx::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), headers, Instant::now())
    }

    #[test]
    fn malformed_emits_signal() {
        let mut h = HeaderMap::new();
        h.append(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("not-an-ip"),
        );
        let v = XffValidator::new(&names(), vec![]).unwrap();
        let signals = v.evaluate(&ctx(&h));
        assert!(signals.contains(&Signal::XffMalformed));
    }

    #[test]
    fn oversize_emits_too_long() {
        let big = "1".repeat(MAX_HEADER_BYTES + 1);
        let mut h = HeaderMap::new();
        h.append(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_str(&big).unwrap(),
        );
        let v = XffValidator::new(&names(), vec![]).unwrap();
        assert!(v.evaluate(&ctx(&h)).contains(&Signal::XffTooLong));
    }

    #[test]
    fn private_mid_chain_emits_spoof() {
        let mut h = HeaderMap::new();
        h.append(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("1.2.3.4, 10.0.0.1, 5.6.7.8"),
        );
        let trusted: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let v = XffValidator::new(&names(), trusted).unwrap();
        assert!(v.evaluate(&ctx(&h)).contains(&Signal::XffSpoofPrivate));
    }

    #[test]
    fn clean_chain_emits_nothing() {
        let mut h = HeaderMap::new();
        h.append(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("1.2.3.4"),
        );
        let v = XffValidator::new(&names(), vec![]).unwrap();
        assert!(v.evaluate(&ctx(&h)).is_empty());
    }
}
