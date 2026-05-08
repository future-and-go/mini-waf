//! FR-025 Phase 2: Tor exit list loader.
//!
//! Loads Tor exit node IPs from a newline-delimited file into a `HashSet`
//! for O(1) lookup. Malformed lines are logged and skipped.

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result};
use tracing::warn;

/// Load Tor exit IPs from a newline-delimited file.
///
/// Each line should be a valid IP address (IPv4 or IPv6).
/// Empty lines and lines starting with `#` are ignored.
/// Malformed lines are logged and skipped.
pub fn load(path: &Path) -> Result<HashSet<IpAddr>> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("failed to read tor exits: {}", path.display()))?;

    Ok(parse_tor_exits(&content, path))
}

/// Parse Tor exit content into a `HashSet`.
fn parse_tor_exits(content: &str, source_path: &Path) -> HashSet<IpAddr> {
    let mut set = HashSet::new();

    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        match trimmed.parse::<IpAddr>() {
            Ok(ip) => {
                set.insert(ip);
            }
            Err(e) => {
                warn!(
                    file = %source_path.display(),
                    line = line_num + 1,
                    content = trimmed,
                    error = %e,
                    "seed/tor: skipping malformed IP"
                );
            }
        }
    }

    set
}

/// Load Tor exits, returning empty set if file doesn't exist.
pub fn load_or_empty(path: &Path) -> HashSet<IpAddr> {
    if !path.exists() {
        return HashSet::new();
    }

    match load(path) {
        Ok(set) => set,
        Err(e) => {
            warn!(file = %path.display(), error = %e, "seed/tor: load failed, using empty");
            HashSet::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use tempfile::tempdir;

    #[test]
    fn parse_valid_ips() {
        let content = r"
# Tor exit nodes
1.2.3.4
5.6.7.8
2607:f8b0:4004:800::200e
";
        let set = parse_tor_exits(content, Path::new("test.txt"));

        assert!(set.contains(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert!(set.contains(&IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8))));
        assert!(set.contains(&IpAddr::V6("2607:f8b0:4004:800::200e".parse().unwrap())));
        assert!(!set.contains(&IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))));
    }

    #[test]
    fn skip_malformed_lines() {
        let content = r"
1.2.3.4
not-an-ip
256.256.256.256
5.6.7.8
";
        let set = parse_tor_exits(content, Path::new("test.txt"));

        assert_eq!(set.len(), 2);
        assert!(set.contains(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert!(set.contains(&IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8))));
    }

    #[test]
    fn load_from_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("tor-exits.txt");

        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "1.2.3.4").unwrap();
        writeln!(f, "# comment").unwrap();
        writeln!(f, "5.6.7.8").unwrap();
        drop(f);

        let set = load(&path).unwrap();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn load_or_empty_handles_missing_file() {
        let set = load_or_empty(Path::new("/nonexistent/tor-exits.txt"));
        assert!(set.is_empty());
    }

    #[test]
    fn ipv6_addresses_parsed() {
        let content = "2001:db8::1\n::1\nfe80::1";
        let set = parse_tor_exits(content, Path::new("test.txt"));

        assert_eq!(set.len(), 3);
        assert!(set.contains(&IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))));
        assert!(set.contains(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }
}
