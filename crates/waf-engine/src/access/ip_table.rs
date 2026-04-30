//! Patricia-trie adapter over `ip_network_table` for dual-stack longest-prefix
//! IP/CIDR matching (FR-008 phase-02).
//!
//! The crate's table already implements longest-prefix matching; we expose
//! only `insert_str` + `contains` so the evaluator stays decoupled from the
//! backing implementation (D9, D11). A future swap to `treebitmap` won't ripple.

use std::net::IpAddr;
use std::str::FromStr;

use anyhow::{Context, anyhow};
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;

/// Dual-stack IP/CIDR set with O(prefix-length) lookup and no allocations on
/// the hot path.
pub struct IpCidrTable {
    table: IpNetworkTable<()>,
    len: usize,
}

impl IpCidrTable {
    #[must_use]
    pub fn new() -> Self {
        Self {
            table: IpNetworkTable::new(),
            len: 0,
        }
    }

    /// Insert a CIDR (`10.0.0.0/8`, `2001:db8::/32`) or bare IP (treated as
    /// `/32` v4 or `/128` v6). Duplicate inserts are silently coalesced.
    pub fn insert_str(&mut self, raw: &str) -> anyhow::Result<()> {
        let net = parse_cidr_or_ip(raw).with_context(|| format!("invalid CIDR/IP: {raw:?}"))?;
        // `insert` returns the previous value for the exact prefix; ignore it.
        let _ = self.table.insert(net, ());
        self.len += 1;
        Ok(())
    }

    /// Longest-prefix membership test. Hot path — no allocations.
    #[inline]
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.table.longest_match(ip).is_some()
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for IpCidrTable {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for IpCidrTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpCidrTable")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

/// Accept either a CIDR string or a bare IP (lifted to a host route).
/// `ip_network` and `ipnet` are different crates — convert at this boundary so
/// only `IpNetwork` leaks into the trie, never the public API.
fn parse_cidr_or_ip(raw: &str) -> anyhow::Result<IpNetwork> {
    if let Ok(net) = IpNetwork::from_str(raw) {
        return Ok(net);
    }
    let ip = IpAddr::from_str(raw).map_err(|_| anyhow!("not a valid CIDR or IP address"))?;
    let host_bits = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    IpNetwork::new(ip, host_bits).map_err(|e| anyhow!("host route construction failed: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_v4_hit() {
        let mut t = IpCidrTable::new();
        t.insert_str("10.0.0.0/8").unwrap();
        assert!(t.contains("10.1.2.3".parse().unwrap()));
        assert!(!t.contains("11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn t_v6_hit() {
        let mut t = IpCidrTable::new();
        t.insert_str("2001:db8::/32").unwrap();
        assert!(t.contains("2001:db8::1".parse().unwrap()));
        assert!(!t.contains("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn t_longest_prefix_wins() {
        // Both /8 and /24 are inserted into the same table; both report a match
        // for an IP inside /24. Allow-vs-deny semantics live in the evaluator
        // (phase-04), not here — this test just verifies trie membership.
        let mut t = IpCidrTable::new();
        t.insert_str("10.0.0.0/8").unwrap();
        t.insert_str("10.0.0.0/24").unwrap();
        assert!(t.contains("10.0.0.5".parse().unwrap()));
        assert!(t.contains("10.1.0.5".parse().unwrap()));
    }

    #[test]
    fn t_miss() {
        let t = IpCidrTable::new();
        assert!(!t.contains("8.8.8.8".parse().unwrap()));
        assert!(t.is_empty());
    }

    #[test]
    fn t_single_ip() {
        let mut t = IpCidrTable::new();
        t.insert_str("192.168.1.5").unwrap();
        assert!(t.contains("192.168.1.5".parse().unwrap()));
        assert!(!t.contains("192.168.1.6".parse().unwrap()));
    }

    #[test]
    fn t_single_ipv6() {
        let mut t = IpCidrTable::new();
        t.insert_str("2001:db8::1").unwrap();
        assert!(t.contains("2001:db8::1".parse().unwrap()));
        assert!(!t.contains("2001:db8::2".parse().unwrap()));
    }

    #[test]
    fn t_malformed() {
        let mut t = IpCidrTable::new();
        let err = t.insert_str("not-an-ip").unwrap_err();
        assert!(format!("{err:#}").contains("not-an-ip"));
    }

    #[test]
    fn t_len_tracks_inserts() {
        let mut t = IpCidrTable::new();
        assert_eq!(t.len(), 0);
        assert!(t.is_empty());
        t.insert_str("10.0.0.0/8").unwrap();
        assert_eq!(t.len(), 1);
        assert!(!t.is_empty());
        t.insert_str("192.168.1.5").unwrap();
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn t_default_constructs_empty_table() {
        let t = IpCidrTable::default();
        assert_eq!(t.len(), 0);
        assert!(t.is_empty());
        assert!(!t.contains("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn t_debug_includes_len_field() {
        let mut t = IpCidrTable::new();
        t.insert_str("10.0.0.0/8").unwrap();
        t.insert_str("192.168.0.0/16").unwrap();
        let s = format!("{t:?}");
        assert!(s.contains("IpCidrTable"));
        assert!(s.contains("len"));
        assert!(s.contains('2'));
    }
}
