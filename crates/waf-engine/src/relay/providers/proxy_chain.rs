//! FR-007 phase-02 — `ProxyChainAnalyzer` provider.
//!
//! Reads the cached `Derived.effective_depth` (chain length minus trusted
//! tail) and emits `ExcessiveHopDepth(n)` when it exceeds
//! `RelayConfig.max_chain_depth`.

use http::HeaderName;
use ipnet::IpNet;

use crate::relay::signal::{RelayCtx, Signal, SignalProvider};

pub struct ProxyChainAnalyzer {
    headers: Vec<HeaderName>,
    trusted: Vec<IpNet>,
    max_depth: u8,
}

impl ProxyChainAnalyzer {
    pub fn new(header_names: &[String], trusted: Vec<IpNet>, max_depth: u8) -> anyhow::Result<Self> {
        let mut headers = Vec::with_capacity(header_names.len());
        for n in header_names {
            let parsed =
                HeaderName::from_bytes(n.as_bytes()).map_err(|e| anyhow::anyhow!("invalid header name {n:?}: {e}"))?;
            headers.push(parsed);
        }
        Ok(Self {
            headers,
            trusted,
            max_depth,
        })
    }
}

impl SignalProvider for ProxyChainAnalyzer {
    fn name(&self) -> &'static str {
        "proxy_chain"
    }

    fn evaluate(&self, ctx: &RelayCtx<'_>) -> Vec<Signal> {
        let d = ctx.populate_derived(&self.headers, &self.trusted);
        if d.effective_depth > self.max_depth {
            vec![Signal::ExcessiveHopDepth(d.effective_depth)]
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn under_cap_silent() {
        let mut h = HeaderMap::new();
        h.append(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("1.1.1.1, 2.2.2.2"),
        );
        let p = ProxyChainAnalyzer::new(&names(), vec![], 3).unwrap();
        assert!(p.evaluate(&ctx(&h)).is_empty());
    }

    #[test]
    fn over_cap_emits_with_depth() {
        let mut h = HeaderMap::new();
        h.append(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("1.1.1.1, 2.2.2.2, 3.3.3.3, 4.4.4.4"),
        );
        let p = ProxyChainAnalyzer::new(&names(), vec![], 3).unwrap();
        let signals = p.evaluate(&ctx(&h));
        assert_eq!(signals, vec![Signal::ExcessiveHopDepth(4)]);
    }

    #[test]
    fn trusted_tail_reduces_effective_depth() {
        let mut h = HeaderMap::new();
        h.append(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("1.1.1.1, 2.2.2.2, 10.0.0.1, 10.0.0.2"),
        );
        let trusted: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let p = ProxyChainAnalyzer::new(&names(), trusted, 3).unwrap();
        assert!(p.evaluate(&ctx(&h)).is_empty());
    }
}
