//! FR-007 phase-03 — datacenter override merge loader.
//!
//! Combines multiple sources into one decision set:
//! - `.txt` file: one ASN per line (`#` comment + blank lines ignored).
//! - `.yaml` file with `asns:` / `cidrs:`: hyperscaler / vendor list.
//! - `.yaml` file with `allow:` / `deny:`: operator override (allow wins
//!   over both built-in DC sets and operator deny).

use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use serde::Deserialize;

#[derive(Default)]
pub struct DatacenterSet {
    pub asn_ids: HashSet<u32>,
    pub cidrs: IpNetworkTable<()>,
    pub operator_allow: HashSet<u32>,
    pub operator_deny: HashSet<u32>,
}

impl std::fmt::Debug for DatacenterSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `cidrs` is `IpNetworkTable<()>` which is not `Debug`; print only
        // size summaries for the other sets.
        f.debug_struct("DatacenterSet")
            .field("asn_ids", &self.asn_ids.len())
            .field("operator_allow", &self.operator_allow.len())
            .field("operator_deny", &self.operator_deny.len())
            .finish_non_exhaustive()
    }
}

/// Single YAML schema covering both override flavors. Empty vectors mean
/// the file did not declare that section.
#[derive(Debug, Default, Deserialize)]
struct YamlDoc {
    #[serde(default)]
    asns: Vec<u32>,
    #[serde(default)]
    cidrs: Vec<String>,
    #[serde(default)]
    allow: Vec<u32>,
    #[serde(default)]
    deny: Vec<u32>,
}

impl DatacenterSet {
    pub fn load(paths: &[PathBuf]) -> Result<Self> {
        let mut set = Self::default();
        for p in paths {
            set.merge_path(p)
                .with_context(|| format!("loading datacenter list {}", p.display()))?;
        }
        Ok(set)
    }

    fn merge_path(&mut self, path: &Path) -> Result<()> {
        let body = fs::read_to_string(path)?;
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        match ext.as_str() {
            "txt" => self.merge_txt(&body),
            "yaml" | "yml" => self.merge_yaml(&body),
            other => Err(anyhow!("unknown datacenter list extension {other:?}")),
        }
    }

    fn merge_txt(&mut self, body: &str) -> Result<()> {
        for raw in body.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let n: u32 = line.parse().with_context(|| format!("parsing ASN line {line:?}"))?;
            self.asn_ids.insert(n);
        }
        Ok(())
    }

    fn merge_yaml(&mut self, body: &str) -> Result<()> {
        let doc: YamlDoc = serde_yaml::from_str(body).context("parsing datacenter YAML")?;
        self.asn_ids.extend(doc.asns);
        for c in doc.cidrs {
            let net: IpNetwork = c.parse().with_context(|| format!("parsing CIDR {c:?}"))?;
            self.cidrs.insert(net, ());
        }
        self.operator_allow.extend(doc.allow);
        self.operator_deny.extend(doc.deny);
        Ok(())
    }

    /// True when `ip` is inside any datacenter CIDR (vendor lists w/o ASN).
    pub fn contains_ip(&self, ip: IpAddr) -> bool {
        self.cidrs.longest_match(ip).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::Ipv4Addr;

    fn tmp(name: &str, body: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::Builder::new().suffix(name).tempfile().expect("temp");
        f.write_all(body.as_bytes()).expect("write");
        f
    }

    #[test]
    fn merges_txt_asn_list() {
        let f = tmp(".txt", "# header\n15169\n8075\n\n");
        let s = DatacenterSet::load(&[f.path().to_path_buf()]).expect("load");
        assert!(s.asn_ids.contains(&15169));
        assert!(s.asn_ids.contains(&8075));
    }

    #[test]
    fn merges_yaml_asns_and_cidrs() {
        let f = tmp(".yaml", "asns: [16509]\ncidrs: [\"203.0.113.0/24\"]\n");
        let s = DatacenterSet::load(&[f.path().to_path_buf()]).expect("load");
        assert!(s.asn_ids.contains(&16509));
        assert!(s.contains_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))));
        assert!(!s.contains_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn operator_override_yaml_split_allow_deny() {
        let f = tmp(".yaml", "allow: [15169]\ndeny: [99999]\n");
        let s = DatacenterSet::load(&[f.path().to_path_buf()]).expect("load");
        assert!(s.operator_allow.contains(&15169));
        assert!(s.operator_deny.contains(&99999));
        assert!(s.asn_ids.is_empty());
    }

    #[test]
    fn rejects_unknown_extension() {
        let f = tmp(".csv", "1,2,3\n");
        assert!(DatacenterSet::load(&[f.path().to_path_buf()]).is_err());
    }
}
