//! FR-025 Phase 2: L0 Reputation Seed Layer.
//!
//! Classifies IPs via whitelist (short-circuit), Tor exit list, and ASN
//! classification before any expensive detection layers run. Uses `ArcSwap`
//! for zero-contention hot-reload.

pub mod asn;
pub mod reload;
pub mod tables;
pub mod tor;
pub mod whitelist;

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tracing::info;

pub use reload::{SeedPaths, SeedReloader};
pub use tables::{AsnClass, SeedTables, SeedTablesBuilder};

use crate::risk::state::SeedKind;

/// Result of seed layer evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SeedVerdict {
    /// IP is whitelisted — short-circuit all remaining layers.
    Whitelisted,
    /// IP matched a seed classification with a risk delta.
    Score { delta: u8, kind: SeedKind },
    /// No seed classification matched.
    None,
}

/// Configuration for seed layer delta values.
#[derive(Clone, Debug)]
pub struct SeedDeltas {
    /// Delta for Tor exit IPs (default: 30).
    pub tor_exit: u8,
    /// Delta for datacenter ASNs (default: 15).
    pub datacenter: u8,
    /// Delta for known-bad ASNs (default: 25).
    pub bad_asn: u8,
}

impl Default for SeedDeltas {
    fn default() -> Self {
        Self {
            tor_exit: 30,
            datacenter: 15,
            bad_asn: 25,
        }
    }
}

/// L0 Reputation Seed Layer.
///
/// Evaluates IPs against whitelist, Tor exits, and ASN classification.
/// Whitelist matches short-circuit all subsequent layers.
pub struct SeedLayer {
    tables: Arc<ArcSwap<SeedTables>>,
    deltas: SeedDeltas,
}

impl SeedLayer {
    /// Create a new seed layer with the given tables and deltas.
    #[must_use]
    pub const fn new(tables: Arc<ArcSwap<SeedTables>>, deltas: SeedDeltas) -> Self {
        Self { tables, deltas }
    }

    /// Create a seed layer with default deltas.
    #[must_use]
    pub fn with_tables(tables: Arc<ArcSwap<SeedTables>>) -> Self {
        Self::new(tables, SeedDeltas::default())
    }

    /// Create an empty seed layer (no data loaded).
    #[must_use]
    pub fn empty() -> Self {
        let tables = Arc::new(ArcSwap::from(Arc::new(SeedTables::empty())));
        Self::with_tables(tables)
    }

    /// Load seed tables from file paths.
    pub fn load_from_paths(
        tor_path: Option<&Path>,
        asn_path: Option<&Path>,
        whitelist_path: Option<&Path>,
        deltas: SeedDeltas,
    ) -> Self {
        let mut builder = SeedTablesBuilder::new();

        if let Some(path) = tor_path {
            for ip in tor::load_or_empty(path) {
                builder.add_tor_exit(ip);
            }
            info!(file = %path.display(), "seed: loaded tor exits");
        }

        if let Some(path) = asn_path {
            let trie = asn::load_or_empty(path);
            for (network, (asn, class)) in trie.iter() {
                builder.add_asn_entry(network, *asn, *class);
            }
            info!(file = %path.display(), "seed: loaded asn classes");
        }

        if let Some(path) = whitelist_path {
            let trie = whitelist::load_or_empty(path);
            for (network, ()) in trie.iter() {
                builder.add_whitelist(network);
            }
            info!(file = %path.display(), "seed: loaded whitelist");
        }

        let tables = Arc::new(ArcSwap::from(builder.build().into_arc()));
        Self::new(tables, deltas)
    }

    /// Get a reference to the underlying `ArcSwap` for hot-reload.
    #[must_use]
    pub const fn tables_swap(&self) -> &Arc<ArcSwap<SeedTables>> {
        &self.tables
    }

    /// Evaluate an IP address.
    ///
    /// Returns `Whitelisted` for short-circuit, `Score` for classification
    /// matches, or `None` if no classification applies.
    #[must_use]
    pub fn evaluate(&self, ip: IpAddr) -> SeedVerdict {
        let tables = self.tables.load();

        // Whitelist check FIRST — short-circuits everything
        if tables.is_whitelisted(ip) {
            return SeedVerdict::Whitelisted;
        }

        // Tor exit check (higher priority than ASN)
        if tables.is_tor_exit(ip) {
            return SeedVerdict::Score {
                delta: self.deltas.tor_exit,
                kind: SeedKind::TorExit,
            };
        }

        // ASN classification
        if let Some((_, class)) = tables.lookup_asn(ip) {
            let (delta, kind) = match class {
                AsnClass::BadAsn => (self.deltas.bad_asn, SeedKind::BadASN),
                AsnClass::Datacenter => (self.deltas.datacenter, SeedKind::DatacenterASN),
                AsnClass::Normal => return SeedVerdict::None,
            };
            return SeedVerdict::Score { delta, kind };
        }

        SeedVerdict::None
    }

    /// Swap tables atomically (used by hot-reload).
    pub fn swap_tables(&self, new_tables: Arc<SeedTables>) {
        self.tables.store(new_tables);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn make_test_layer() -> SeedLayer {
        let mut builder = SeedTablesBuilder::new();

        // Whitelist
        builder.add_whitelist("10.0.0.0/8".parse().unwrap());
        builder.add_whitelist("192.168.0.0/16".parse().unwrap());

        // Tor exits
        builder.add_tor_exit(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        builder.add_tor_exit(IpAddr::V6(Ipv6Addr::new(0x2607, 0xf8b0, 0, 0, 0, 0, 0, 1)));

        // ASN classifications
        builder.add_asn_entry("52.0.0.0/8".parse().unwrap(), 16509, AsnClass::Datacenter);
        builder.add_asn_entry("185.220.0.0/16".parse().unwrap(), 12345, AsnClass::BadAsn);

        let tables = Arc::new(ArcSwap::from(builder.build().into_arc()));
        SeedLayer::with_tables(tables)
    }

    #[test]
    fn whitelist_returns_whitelisted() {
        let layer = make_test_layer();

        assert_eq!(
            layer.evaluate(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))),
            SeedVerdict::Whitelisted
        );
        assert_eq!(
            layer.evaluate(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            SeedVerdict::Whitelisted
        );
    }

    #[test]
    fn tor_exit_returns_score() {
        let layer = make_test_layer();

        let verdict = layer.evaluate(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(
            verdict,
            SeedVerdict::Score {
                delta: 30,
                kind: SeedKind::TorExit
            }
        );
    }

    #[test]
    fn datacenter_asn_returns_score() {
        let layer = make_test_layer();

        let verdict = layer.evaluate(IpAddr::V4(Ipv4Addr::new(52, 94, 1, 1)));
        assert_eq!(
            verdict,
            SeedVerdict::Score {
                delta: 15,
                kind: SeedKind::DatacenterASN
            }
        );
    }

    #[test]
    fn bad_asn_returns_score() {
        let layer = make_test_layer();

        let verdict = layer.evaluate(IpAddr::V4(Ipv4Addr::new(185, 220, 1, 1)));
        assert_eq!(
            verdict,
            SeedVerdict::Score {
                delta: 25,
                kind: SeedKind::BadASN
            }
        );
    }

    #[test]
    fn unknown_ip_returns_none() {
        let layer = make_test_layer();

        let verdict = layer.evaluate(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(verdict, SeedVerdict::None);
    }

    #[test]
    fn ipv6_tor_exit_detected() {
        let layer = make_test_layer();

        let verdict = layer.evaluate(IpAddr::V6(Ipv6Addr::new(0x2607, 0xf8b0, 0, 0, 0, 0, 0, 1)));
        assert_eq!(
            verdict,
            SeedVerdict::Score {
                delta: 30,
                kind: SeedKind::TorExit
            }
        );
    }

    #[test]
    fn empty_layer_returns_none() {
        let layer = SeedLayer::empty();
        let verdict = layer.evaluate(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(verdict, SeedVerdict::None);
    }

    #[test]
    fn hot_reload_swap_works() {
        let layer = SeedLayer::empty();

        // Initially empty
        assert_eq!(layer.evaluate(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))), SeedVerdict::None);

        // Swap in new tables with Tor exit
        let mut builder = SeedTablesBuilder::new();
        builder.add_tor_exit(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        layer.swap_tables(builder.build().into_arc());

        // Now detected
        let verdict = layer.evaluate(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(
            verdict,
            SeedVerdict::Score {
                delta: 30,
                kind: SeedKind::TorExit
            }
        );
    }
}
