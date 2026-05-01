//! FR-007 phase-01 — public signal types + provider trait.
//!
//! Pure data + traits. No I/O. Phases 02-04 plug providers into
//! `ProviderRegistry` against this stable contract.

use std::cell::OnceCell;
use std::net::IpAddr;
use std::time::Instant;

use http::{HeaderMap, HeaderName};
use ipnet::IpNet;

use crate::relay::providers::parse::{DeriveOutcome, ParsedChain, derive_real_ip, parse_xff_chain};

/// Coarse classification of the originating ASN.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AsnClass {
    Residential,
    Datacenter,
    Tor,
    Unknown,
}

/// Discrete relay/proxy detections emitted by `SignalProvider`s.
///
/// Flat enum (not trait object) so the risk scorer in FR-025 can match
/// exhaustively and the compiler flags missing branches when new variants
/// land.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signal {
    /// XFF carried a private/loopback address from outside `trusted_proxies`.
    XffSpoofPrivate,
    /// XFF header failed parse (non-IP token).
    XffMalformed,
    /// XFF chain length exceeded `max_chain_depth`.
    XffTooLong,
    /// Hop depth observed is `n`, beyond configured cap.
    ExcessiveHopDepth(u8),
    /// Real IP is owned by a known datacenter/cloud ASN.
    AsnDatacenter { asn: u32, org: String },
    /// Real IP is on a residential ASN.
    AsnResidential,
    /// ASN database had no record for this IP.
    AsnUnknown,
    /// Real IP is currently published as a Tor exit relay.
    TorExit,
}

/// Resolved client view emitted by `RelayDetector::evaluate`.
#[derive(Clone, Debug)]
pub struct ClientIdentity {
    pub real_ip: IpAddr,
    pub asn: Option<u32>,
    pub asn_class: AsnClass,
    pub signals: Vec<Signal>,
}

/// Cached per-request derivation populated lazily on first provider call.
/// Subsequent providers reuse without re-parsing (phase-02 §Architecture).
#[derive(Debug, Clone)]
pub struct Derived {
    pub parsed: ParsedChain,
    pub real_ip: IpAddr,
    pub stripped_count: u8,
    pub spoof_private_mid_chain: bool,
    /// Chain length minus stripped trusted tail.
    pub effective_depth: u8,
}

/// Per-request input passed to every `SignalProvider`.
///
/// Borrowed-only to keep the hot path allocation-free; lifetime tied to the
/// inbound request's `HeaderMap`. Holds a `OnceCell<Derived>` so the first
/// provider that needs a parsed XFF chain populates it; later providers
/// (`ProxyChainAnalyzer`, `AsnClassifier`) reuse the cached real-IP.
pub struct RelayCtx<'a> {
    pub peer_ip: IpAddr,
    pub headers: &'a HeaderMap,
    pub now: Instant,
    derived: OnceCell<Derived>,
}

impl<'a> RelayCtx<'a> {
    #[must_use]
    pub const fn new(peer_ip: IpAddr, headers: &'a HeaderMap, now: Instant) -> Self {
        Self {
            peer_ip,
            headers,
            now,
            derived: OnceCell::new(),
        }
    }

    /// Populate (or read) cached parse + derivation. Both `header_names`
    /// and `trusted` come from the active `RelayConfig`; callers must pass
    /// the same slices each time so the cache is consistent.
    pub fn populate_derived(&self, header_names: &[HeaderName], trusted: &[IpNet]) -> &Derived {
        self.derived.get_or_init(|| {
            let parsed = parse_xff_chain(self.headers, header_names);
            let chain: &[IpAddr] = if parsed.has_error() { &[] } else { &parsed.entries };
            let DeriveOutcome {
                real_ip,
                stripped_count,
                spoof_private_mid_chain,
            } = derive_real_ip(chain, trusted, self.peer_ip);
            let effective_depth = u8::try_from(chain.len().saturating_sub(stripped_count as usize)).unwrap_or(u8::MAX);
            Derived {
                parsed,
                real_ip,
                stripped_count,
                spoof_private_mid_chain,
                effective_depth,
            }
        })
    }

    /// Read the cached derivation without populating it (returns None if no
    /// provider has populated yet).
    #[must_use]
    pub fn derived(&self) -> Option<&Derived> {
        self.derived.get()
    }
}

/// A pluggable detection unit. Implementations stay stateless w.r.t. the
/// request — any shared state (ASN db, Tor set) is captured at construction
/// behind an `ArcSwap`.
pub trait SignalProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn evaluate(&self, ctx: &RelayCtx<'_>) -> Vec<Signal>;
}
