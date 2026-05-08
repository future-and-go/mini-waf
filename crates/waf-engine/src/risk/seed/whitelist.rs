//! FR-025 Phase 2: Whitelist CIDR loader.
//!
//! Loads whitelist CIDRs from a newline-delimited file. Malformed lines are
//! logged and skipped — never panics.

use std::path::Path;

use anyhow::{Context, Result};
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use tracing::warn;

/// Load whitelist CIDRs from a newline-delimited file.
///
/// Each line should be a valid CIDR (e.g., `10.0.0.0/8` or `2001:db8::/32`).
/// Empty lines and lines starting with `#` are ignored.
/// Malformed lines are logged and skipped.
pub fn load(path: &Path) -> Result<IpNetworkTable<()>> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("failed to read whitelist: {}", path.display()))?;

    Ok(parse_whitelist(&content, path))
}

/// Parse whitelist content into a trie.
fn parse_whitelist(content: &str, source_path: &Path) -> IpNetworkTable<()> {
    let mut trie = IpNetworkTable::new();

    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        match trimmed.parse::<IpNetwork>() {
            Ok(network) => {
                trie.insert(network, ());
            }
            Err(e) => {
                warn!(
                    file = %source_path.display(),
                    line = line_num + 1,
                    content = trimmed,
                    error = %e,
                    "seed/whitelist: skipping malformed CIDR"
                );
            }
        }
    }

    trie
}

/// Load whitelist, returning empty trie if file doesn't exist.
pub fn load_or_empty(path: &Path) -> IpNetworkTable<()> {
    if !path.exists() {
        return IpNetworkTable::new();
    }

    match load(path) {
        Ok(trie) => trie,
        Err(e) => {
            warn!(file = %path.display(), error = %e, "seed/whitelist: load failed, using empty");
            IpNetworkTable::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use tempfile::tempdir;

    #[test]
    fn parse_valid_cidrs() {
        let content = r"
# Internal networks
10.0.0.0/8
192.168.0.0/16
# IPv6
2001:db8::/32
";
        let trie = parse_whitelist(content, Path::new("test.txt"));

        assert!(trie.longest_match(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))).is_some());
        assert!(trie.longest_match(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))).is_some());
        assert!(
            trie.longest_match(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)))
                .is_some()
        );
        assert!(trie.longest_match(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))).is_none());
    }

    #[test]
    fn skip_malformed_lines() {
        let content = r"
10.0.0.0/8
not-a-cidr
192.168.0.0/33
172.16.0.0/12
";
        let trie = parse_whitelist(content, Path::new("test.txt"));

        assert!(trie.longest_match(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))).is_some());
        assert!(trie.longest_match(IpAddr::V4(Ipv4Addr::new(172, 16, 1, 1))).is_some());
    }

    #[test]
    fn load_from_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("whitelist.txt");

        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "10.0.0.0/8").unwrap();
        writeln!(f, "# comment").unwrap();
        writeln!(f, "192.168.0.0/16").unwrap();
        drop(f);

        let trie = load(&path).unwrap();
        assert!(trie.longest_match(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).is_some());
        assert!(trie.longest_match(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))).is_some());
    }

    #[test]
    fn load_or_empty_handles_missing_file() {
        let trie = load_or_empty(Path::new("/nonexistent/whitelist.txt"));
        assert!(trie.longest_match(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).is_none());
    }
}
