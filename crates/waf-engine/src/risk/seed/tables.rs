//! FR-025 Phase 2: Seed data tables for L0 reputation layer.
//!
//! Bundles Tor exit set, ASN classification trie, and whitelist CIDR trie
//! into a single `SeedTables` struct for atomic hot-reload via `ArcSwap`.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;

/// ASN classification category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AsnClass {
    /// AWS, GCP, Azure, DO, OVH, Hetzner, Linode, etc.
    Datacenter,
    /// Operator-curated known-bad ASN list.
    BadAsn,
    /// Residential or unclassified.
    Normal,
}

/// Bundled seed data tables for atomic swap.
pub struct SeedTables {
    /// Tor exit node IPs (IPv4 + IPv6).
    pub tor_exits: HashSet<IpAddr>,
    /// ASN classification trie: CIDR -> (ASN number, classification).
    pub asn_trie: IpNetworkTable<(u32, AsnClass)>,
    /// Whitelist CIDR trie (value is unit — presence means whitelisted).
    pub whitelist: IpNetworkTable<()>,
}

impl Default for SeedTables {
    fn default() -> Self {
        Self::empty()
    }
}

impl SeedTables {
    /// Create empty tables (used on startup if data files don't exist).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            tor_exits: HashSet::new(),
            asn_trie: IpNetworkTable::new(),
            whitelist: IpNetworkTable::new(),
        }
    }

    /// Wrap in Arc for `ArcSwap` storage.
    #[must_use]
    pub fn into_arc(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Check if IP is in the whitelist.
    #[must_use]
    pub fn is_whitelisted(&self, ip: IpAddr) -> bool {
        self.whitelist.longest_match(ip).is_some()
    }

    /// Check if IP is a known Tor exit.
    #[must_use]
    pub fn is_tor_exit(&self, ip: IpAddr) -> bool {
        self.tor_exits.contains(&ip)
    }

    /// Lookup ASN classification for an IP.
    #[must_use]
    pub fn lookup_asn(&self, ip: IpAddr) -> Option<(u32, AsnClass)> {
        self.asn_trie.longest_match(ip).map(|(_, &v)| v)
    }
}

/// Builder for constructing `SeedTables` incrementally.
pub struct SeedTablesBuilder {
    tor_exits: HashSet<IpAddr>,
    asn_trie: IpNetworkTable<(u32, AsnClass)>,
    whitelist: IpNetworkTable<()>,
}

impl Default for SeedTablesBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SeedTablesBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tor_exits: HashSet::new(),
            asn_trie: IpNetworkTable::new(),
            whitelist: IpNetworkTable::new(),
        }
    }

    /// Add a Tor exit IP.
    pub fn add_tor_exit(&mut self, ip: IpAddr) {
        self.tor_exits.insert(ip);
    }

    /// Add an ASN classification entry.
    pub fn add_asn_entry(&mut self, network: IpNetwork, asn: u32, class: AsnClass) {
        self.asn_trie.insert(network, (asn, class));
    }

    /// Add a whitelist CIDR.
    pub fn add_whitelist(&mut self, network: IpNetwork) {
        self.whitelist.insert(network, ());
    }

    /// Build the final tables.
    #[must_use]
    pub fn build(self) -> SeedTables {
        SeedTables {
            tor_exits: self.tor_exits,
            asn_trie: self.asn_trie,
            whitelist: self.whitelist,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn empty_tables_return_none() {
        let tables = SeedTables::empty();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        assert!(!tables.is_whitelisted(ip));
        assert!(!tables.is_tor_exit(ip));
        assert!(tables.lookup_asn(ip).is_none());
    }

    #[test]
    fn whitelist_lookup_works() {
        let mut builder = SeedTablesBuilder::new();
        builder.add_whitelist("10.0.0.0/8".parse().unwrap());
        let tables = builder.build();

        assert!(tables.is_whitelisted(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(!tables.is_whitelisted(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn tor_exit_lookup_works() {
        let mut builder = SeedTablesBuilder::new();
        let tor_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        builder.add_tor_exit(tor_ip);
        let tables = builder.build();

        assert!(tables.is_tor_exit(tor_ip));
        assert!(!tables.is_tor_exit(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8))));
    }

    #[test]
    fn asn_lookup_returns_longest_match() {
        let mut builder = SeedTablesBuilder::new();
        builder.add_asn_entry("52.0.0.0/8".parse().unwrap(), 16509, AsnClass::Datacenter);
        builder.add_asn_entry("52.94.0.0/16".parse().unwrap(), 16509, AsnClass::BadAsn);
        let tables = builder.build();

        // Specific /16 should win over /8
        let (asn, class) = tables.lookup_asn(IpAddr::V4(Ipv4Addr::new(52, 94, 1, 1))).unwrap();
        assert_eq!(asn, 16509);
        assert_eq!(class, AsnClass::BadAsn);

        // Outside /16 should get /8
        let (asn, class) = tables.lookup_asn(IpAddr::V4(Ipv4Addr::new(52, 1, 1, 1))).unwrap();
        assert_eq!(asn, 16509);
        assert_eq!(class, AsnClass::Datacenter);
    }

    #[test]
    fn ipv6_lookup_works() {
        let mut builder = SeedTablesBuilder::new();
        builder.add_whitelist("2001:db8::/32".parse().unwrap());
        builder.add_tor_exit(IpAddr::V6(Ipv6Addr::new(0x2607, 0xf8b0, 0, 0, 0, 0, 0, 1)));
        let tables = builder.build();

        assert!(tables.is_whitelisted(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))));
        assert!(tables.is_tor_exit(IpAddr::V6(Ipv6Addr::new(0x2607, 0xf8b0, 0, 0, 0, 0, 0, 1))));
    }
}
