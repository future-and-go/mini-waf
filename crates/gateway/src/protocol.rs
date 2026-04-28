//! Per-protocol identification and traffic counters (phase-05, AC-22).
//!
//! Every listener (H1, H2, H3, WS-upgrade) routes through the same WAF
//! pipeline. To prove transparency we tag each request with its protocol
//! and bump a per-protocol counter alongside the global one.
//!
//! Detection rules:
//! - WS: request carries `Upgrade: websocket` (handshake-only — frames
//!   post-upgrade are forwarded opaquely; see phase-05 plan).
//! - H2: Pingora `Session::is_http2()` is true.
//! - H1: default.
//! - H3: detected at the QUIC entry point (`http3.rs`) — never produced by
//!   the Pingora path.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use pingora_proxy::Session;

/// Wire protocol of an inbound request.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    #[default]
    H1,
    H2,
    H3,
    Websocket,
}

impl Protocol {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::H1 => "h1",
            Self::H2 => "h2",
            Self::H3 => "h3",
            Self::Websocket => "ws",
        }
    }
}

/// Detect the protocol of an inbound Pingora session.
///
/// WS handshake takes precedence over H1/H2 since it can occur over either
/// transport — the upgrade is the more specific classification.
pub fn detect_from_session(session: &Session) -> Protocol {
    let is_ws_upgrade = session
        .get_header("upgrade")
        .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    if is_ws_upgrade {
        return Protocol::Websocket;
    }
    if session.is_http2() { Protocol::H2 } else { Protocol::H1 }
}

/// Per-protocol request counters. Cloned across `WafProxy` and the H3
/// listener so AC-22 holds regardless of the entry path.
#[derive(Debug, Default)]
pub struct ProtoCounters {
    pub h1: AtomicU64,
    pub h2: AtomicU64,
    pub h3: AtomicU64,
    pub ws: AtomicU64,
}

impl ProtoCounters {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn record(&self, proto: Protocol) {
        let cell = match proto {
            Protocol::H1 => &self.h1,
            Protocol::H2 => &self.h2,
            Protocol::H3 => &self.h3,
            Protocol::Websocket => &self.ws,
        };
        cell.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get(&self, proto: Protocol) -> u64 {
        let cell = match proto {
            Protocol::H1 => &self.h1,
            Protocol::H2 => &self.h2,
            Protocol::H3 => &self.h3,
            Protocol::Websocket => &self.ws,
        };
        cell.load(Ordering::Relaxed)
    }

    pub fn total(&self) -> u64 {
        self.h1.load(Ordering::Relaxed)
            + self.h2.load(Ordering::Relaxed)
            + self.h3.load(Ordering::Relaxed)
            + self.ws.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_isolates_per_protocol_buckets() {
        let c = ProtoCounters::default();
        c.record(Protocol::H1);
        c.record(Protocol::H2);
        c.record(Protocol::H2);
        c.record(Protocol::H3);
        c.record(Protocol::Websocket);

        assert_eq!(c.get(Protocol::H1), 1);
        assert_eq!(c.get(Protocol::H2), 2);
        assert_eq!(c.get(Protocol::H3), 1);
        assert_eq!(c.get(Protocol::Websocket), 1);
        assert_eq!(c.total(), 5);
    }

    #[test]
    fn protocol_as_str_matches_phase05_labels() {
        assert_eq!(Protocol::H1.as_str(), "h1");
        assert_eq!(Protocol::H2.as_str(), "h2");
        assert_eq!(Protocol::H3.as_str(), "h3");
        assert_eq!(Protocol::Websocket.as_str(), "ws");
    }

    #[test]
    fn new_returns_zeroed_counters() {
        let c = ProtoCounters::new();
        assert_eq!(c.get(Protocol::H1), 0);
        assert_eq!(c.get(Protocol::H2), 0);
        assert_eq!(c.get(Protocol::H3), 0);
        assert_eq!(c.get(Protocol::Websocket), 0);
        assert_eq!(c.total(), 0);
    }
}
