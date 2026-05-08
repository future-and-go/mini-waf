//! FR-025 Phase 2: ASN classification loader.
//!
//! Loads ASN classification data from a CSV file into a radix trie for
//! longest-prefix matching. Format: `cidr,asn,classification`.

use std::path::Path;

use anyhow::{Context, Result};
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use tracing::warn;

use super::tables::AsnClass;

/// Load ASN classification from a CSV file.
///
/// Expected format: `cidr,asn,classification`
/// - `cidr`: IP network in CIDR notation (e.g., `52.0.0.0/8`)
/// - `asn`: AS number (e.g., `16509`)
/// - `classification`: one of `datacenter`, `badlist`, `normal`
///
/// Lines starting with `#` are comments. Malformed lines are skipped.
pub fn load(path: &Path) -> Result<IpNetworkTable<(u32, AsnClass)>> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("failed to read asn classes: {}", path.display()))?;

    Ok(parse_asn_csv(&content, path))
}

/// Parse ASN CSV content into a trie.
fn parse_asn_csv(content: &str, source_path: &Path) -> IpNetworkTable<(u32, AsnClass)> {
    let mut trie = IpNetworkTable::new();

    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        match parse_asn_line(trimmed) {
            Ok((network, asn, class)) => {
                trie.insert(network, (asn, class));
            }
            Err(e) => {
                warn!(
                    file = %source_path.display(),
                    line = line_num + 1,
                    content = trimmed,
                    error = %e,
                    "seed/asn: skipping malformed line"
                );
            }
        }
    }

    trie
}

/// Parse a single ASN CSV line.
fn parse_asn_line(line: &str) -> Result<(IpNetwork, u32, AsnClass)> {
    let parts: Vec<&str> = line.split(',').map(str::trim).collect();

    let [cidr, asn_str, class_str, ..] = parts.as_slice() else {
        anyhow::bail!("expected 3 columns: cidr,asn,classification");
    };

    let network: IpNetwork = cidr.parse().with_context(|| format!("invalid CIDR: {cidr}"))?;

    let asn: u32 = asn_str.parse().with_context(|| format!("invalid ASN: {asn_str}"))?;

    let class = match class_str.to_lowercase().as_str() {
        "datacenter" | "dc" => AsnClass::Datacenter,
        "badlist" | "bad" | "badasn" => AsnClass::BadAsn,
        "normal" | "residential" | "res" => AsnClass::Normal,
        other => anyhow::bail!("unknown classification: {other}"),
    };

    Ok((network, asn, class))
}

/// Load ASN data, returning empty trie if file doesn't exist.
pub fn load_or_empty(path: &Path) -> IpNetworkTable<(u32, AsnClass)> {
    if !path.exists() {
        return IpNetworkTable::new();
    }

    match load(path) {
        Ok(trie) => trie,
        Err(e) => {
            warn!(file = %path.display(), error = %e, "seed/asn: load failed, using empty");
            IpNetworkTable::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr};
    use tempfile::tempdir;

    #[test]
    fn parse_valid_csv() {
        let content = r"
# AWS ranges
52.0.0.0/8,16509,datacenter
# Bad ASN
185.220.0.0/16,12345,badlist
# Residential
203.0.113.0/24,99999,normal
";
        let trie = parse_asn_csv(content, Path::new("test.csv"));

        let (asn, class) = trie.longest_match(IpAddr::V4(Ipv4Addr::new(52, 1, 2, 3))).unwrap().1;
        assert_eq!(*asn, 16509);
        assert_eq!(*class, AsnClass::Datacenter);

        let (asn, class) = trie.longest_match(IpAddr::V4(Ipv4Addr::new(185, 220, 1, 1))).unwrap().1;
        assert_eq!(*asn, 12345);
        assert_eq!(*class, AsnClass::BadAsn);
    }

    #[test]
    fn parse_line_variants() {
        assert!(parse_asn_line("10.0.0.0/8, 12345, dc").is_ok());
        assert!(parse_asn_line("10.0.0.0/8, 12345, bad").is_ok());
        assert!(parse_asn_line("10.0.0.0/8, 12345, res").is_ok());
    }

    #[test]
    fn skip_malformed_lines() {
        let content = r"
52.0.0.0/8,16509,datacenter
invalid-cidr,12345,datacenter
52.0.0.0/8,not-a-number,datacenter
52.0.0.0/8,12345,unknown-class
10.0.0.0/8,99999,normal
";
        let trie = parse_asn_csv(content, Path::new("test.csv"));

        // Only 2 valid entries
        assert!(trie.longest_match(IpAddr::V4(Ipv4Addr::new(52, 1, 2, 3))).is_some());
        assert!(trie.longest_match(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))).is_some());
    }

    #[test]
    fn longest_prefix_match() {
        let content = r"
52.0.0.0/8,16509,datacenter
52.94.0.0/16,16509,badlist
";
        let trie = parse_asn_csv(content, Path::new("test.csv"));

        // /16 should win over /8 for 52.94.x.x
        let (_, class) = trie.longest_match(IpAddr::V4(Ipv4Addr::new(52, 94, 1, 1))).unwrap().1;
        assert_eq!(*class, AsnClass::BadAsn);

        // Outside /16 should get /8
        let (_, class) = trie.longest_match(IpAddr::V4(Ipv4Addr::new(52, 1, 1, 1))).unwrap().1;
        assert_eq!(*class, AsnClass::Datacenter);
    }

    #[test]
    fn load_from_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("asn-classes.csv");

        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "# AWS").unwrap();
        writeln!(f, "52.0.0.0/8,16509,datacenter").unwrap();
        drop(f);

        let trie = load(&path).unwrap();
        assert!(trie.longest_match(IpAddr::V4(Ipv4Addr::new(52, 1, 2, 3))).is_some());
    }

    #[test]
    fn load_or_empty_handles_missing_file() {
        let trie = load_or_empty(Path::new("/nonexistent/asn.csv"));
        assert!(trie.longest_match(IpAddr::V4(Ipv4Addr::new(52, 1, 2, 3))).is_none());
    }
}
