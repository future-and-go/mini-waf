//! FR-007 phase-04 — Tor exit relay matcher.
//!
//! `TorSet` is a `HashSet<IpAddr>` loaded from the Tor Project exit list
//! (one IP per line, `#`-comments + blanks ignored). Wrapped in
//! `ArcSwap` so the refresh task in `intel::tor_feed` can atomically
//! publish a new snapshot without locking readers.

use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use arc_swap::ArcSwap;

use crate::relay::signal::{RelayCtx, Signal, SignalProvider};

/// Hard cap on entries — published Tor exit list is ~1.5k IPs in practice;
/// 1M is room for several orders of magnitude of growth before we treat
/// the file as malformed/poisoned.
const MAX_ENTRIES: usize = 1_000_000;

#[derive(Default)]
pub struct TorSet {
    ips: HashSet<IpAddr>,
}

impl TorSet {
    #[must_use]
    pub const fn new(ips: HashSet<IpAddr>) -> Self {
        Self { ips }
    }

    /// Parse a Tor exit list file. Skips blank lines and `#`-prefixed
    /// comments. Lines that fail to parse as IP are skipped with a debug
    /// trace (poisoned-feed mitigation: a single bad line cannot brick
    /// the whole list — but oversize is rejected outright).
    pub fn load(path: &Path) -> Result<Self> {
        let body = fs::read_to_string(path).with_context(|| format!("reading Tor exit list {}", path.display()))?;
        Self::parse(&body)
    }

    pub fn parse(body: &str) -> Result<Self> {
        let mut ips = HashSet::new();
        for raw in body.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match line.parse::<IpAddr>() {
                Ok(ip) => {
                    ips.insert(ip);
                    if ips.len() > MAX_ENTRIES {
                        bail!("Tor exit list exceeded {MAX_ENTRIES} entries");
                    }
                }
                Err(_) => {
                    tracing::debug!(line = %raw, "skipping malformed Tor exit entry");
                }
            }
        }
        Ok(Self { ips })
    }

    #[must_use]
    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.ips.contains(ip)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.ips.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ips.is_empty()
    }
}

/// Signal provider that emits `Signal::TorExit` when the request's resolved
/// `real_ip` is on the published Tor exit list.
pub struct TorExitMatcher {
    set: Arc<ArcSwap<TorSet>>,
}

impl TorExitMatcher {
    #[must_use]
    pub const fn new(set: Arc<ArcSwap<TorSet>>) -> Self {
        Self { set }
    }

    /// Convenience builder for callers without an existing `ArcSwap`.
    #[must_use]
    pub fn from_set(set: TorSet) -> Self {
        Self::new(Arc::new(ArcSwap::from(Arc::new(set))))
    }

    #[must_use]
    pub fn handle(&self) -> Arc<ArcSwap<TorSet>> {
        Arc::clone(&self.set)
    }
}

impl SignalProvider for TorExitMatcher {
    fn name(&self) -> &'static str {
        "tor_exit"
    }

    fn evaluate(&self, ctx: &RelayCtx<'_>) -> Vec<Signal> {
        // We rely on the `real_ip` cache populated by xff/proxy_chain
        // providers earlier in the registry. If no upstream provider has
        // populated the cache yet, fall back to peer_ip directly — this
        // keeps the Tor matcher useful in minimal configs where only
        // `tor_exit` is enabled.
        let real_ip = ctx.derived().map_or(ctx.peer_ip, |d| d.real_ip);
        let snap = self.set.load();
        if snap.contains(&real_ip) {
            vec![Signal::TorExit]
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;
    use std::net::Ipv4Addr;
    use std::time::Instant;

    #[test]
    fn parses_comments_and_blanks() {
        let body = "# comment\n\n203.0.113.1\n203.0.113.2\n# another\n";
        let s = TorSet::parse(body).expect("parse");
        assert_eq!(s.len(), 2);
        assert!(s.contains(&IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))));
    }

    #[test]
    fn skips_malformed_lines() {
        let body = "203.0.113.1\nnot-an-ip\n203.0.113.2\n";
        let s = TorSet::parse(body).expect("parse");
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn matcher_emits_tor_exit_on_hit() {
        let mut set = HashSet::new();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        set.insert(ip);
        let m = TorExitMatcher::from_set(TorSet::new(set));
        let headers = HeaderMap::new();
        let ctx = RelayCtx::new(ip, &headers, Instant::now());
        assert_eq!(m.evaluate(&ctx), vec![Signal::TorExit]);
    }

    #[test]
    fn matcher_silent_on_miss() {
        let m = TorExitMatcher::from_set(TorSet::default());
        let headers = HeaderMap::new();
        let ctx = RelayCtx::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), &headers, Instant::now());
        assert!(m.evaluate(&ctx).is_empty());
    }
}
