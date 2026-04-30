//! YAML schema + parser for `rules/access-lists.yaml` (FR-008 phase-01).
//!
//! Pure data + validation. No trie build, no host-set build — those land in
//! phases 02 and 03 respectively. The shape here is the public stable contract
//! every later phase compiles against.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, bail};
use ipnet::IpNet;
use serde::Deserialize;
use waf_common::tier::Tier;

use crate::access::host_gate::HostGate;
use crate::access::ip_table::IpCidrTable;

/// Hard cap — parser rejects YAML beyond this entry count to bound memory.
const HARD_REJECT_ENTRIES: usize = 500_000;
/// Soft cap — emit `tracing::warn!` past this point.
const SOFT_WARN_ENTRIES: usize = 50_000;
/// Currently the only supported schema version. Bumped on breaking change.
const SUPPORTED_VERSION: u32 = 1;

/// How a per-tier whitelist hit short-circuits the WAF pipeline.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WhitelistMode {
    /// Skip every downstream check (fast path).
    FullBypass,
    /// Run rules even if whitelisted (defense-in-depth, default).
    // D4 / risk-register: safer default. A typo must not silently bypass rules.
    #[default]
    BlacklistOnly,
}

/// 1:1 mirror of `rules/access-lists.yaml`. All fields optional so partial
/// configs (or an empty file) parse to a "everything disabled" snapshot — D4.
#[derive(Debug, Default, Deserialize)]
pub struct AccessConfig {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub ip_whitelist: Vec<String>,
    #[serde(default)]
    pub ip_blacklist: Vec<String>,
    #[serde(default)]
    pub host_whitelist: HashMap<Tier, Vec<String>>,
    #[serde(default)]
    pub tier_whitelist_mode: HashMap<Tier, WhitelistMode>,
}

impl AccessConfig {
    /// End-to-end syntactic + semantic validation. Trie/host-set construction
    /// is deferred to phases 02-03; here we only ensure the file is well-formed
    /// and within size caps.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.version != SUPPORTED_VERSION {
            bail!(
                "unsupported access-lists version {}: expected {SUPPORTED_VERSION}",
                self.version
            );
        }

        let total = self.ip_whitelist.len() + self.ip_blacklist.len();
        if total > HARD_REJECT_ENTRIES {
            bail!("access-list entry count {total} exceeds hard cap of {HARD_REJECT_ENTRIES}");
        }
        if total > SOFT_WARN_ENTRIES {
            tracing::warn!(
                entries = total,
                soft_cap = SOFT_WARN_ENTRIES,
                "access-list size approaching hard cap"
            );
        }

        for (idx, cidr) in self.ip_whitelist.iter().enumerate() {
            parse_cidr_or_ip(cidr).with_context(|| format!("ip_whitelist[{idx}] invalid CIDR/IP: {cidr:?}"))?;
        }
        for (idx, cidr) in self.ip_blacklist.iter().enumerate() {
            parse_cidr_or_ip(cidr).with_context(|| format!("ip_blacklist[{idx}] invalid CIDR/IP: {cidr:?}"))?;
        }

        for (tier, hosts) in &self.host_whitelist {
            for (idx, host) in hosts.iter().enumerate() {
                validate_host(host).with_context(|| format!("host_whitelist[{tier:?}][{idx}]: {host:?}"))?;
            }
        }

        Ok(())
    }
}

/// Accept either CIDR (`10.0.0.0/8`) or bare IP (`192.168.1.5`). The brainstorm
/// schema treats a bare IP as a /32 (or /128 for v6); phase-02 normalizes both
/// forms when building the trie.
fn parse_cidr_or_ip(s: &str) -> anyhow::Result<()> {
    if IpNet::from_str(s).is_ok() || IpAddr::from_str(s).is_ok() {
        return Ok(());
    }
    bail!("invalid IP address syntax")
}

/// Hosts must be lowercase, no port, no whitespace — a port suffix or upper-case
/// letter would silently miss at lookup time (`Host` header is normalized
/// pre-lookup), which is the kind of failure that locks tenants out of prod.
fn validate_host(host: &str) -> anyhow::Result<()> {
    if host.is_empty() {
        bail!("empty host");
    }
    if host.contains(':') {
        bail!("port suffix not allowed");
    }
    if host.chars().any(char::is_whitespace) {
        bail!("whitespace not allowed");
    }
    if host.chars().any(|c| c.is_ascii_uppercase()) {
        bail!("must be lowercase");
    }
    Ok(())
}

/// Immutable runtime aggregate. Phase-02..04 will replace `config` with
/// pre-built `IpCidrTable` + `HostGate` fields. For phase-01 we keep the raw
/// validated config so later phases have a stable input.
#[derive(Debug)]
pub struct AccessLists {
    config: AccessConfig,
    ip_whitelist: IpCidrTable,
    ip_blacklist: IpCidrTable,
    host_gate: HostGate,
}

impl AccessLists {
    /// All gates disabled — used at boot before the YAML loader runs and as
    /// fallback when the file is missing.
    #[must_use]
    pub fn empty() -> Arc<Self> {
        // Default config has version=0 which would fail validate(); skip
        // validation here because the empty snapshot is internally constructed,
        // not user-provided.
        Arc::new(Self {
            config: AccessConfig {
                version: SUPPORTED_VERSION,
                ..AccessConfig::default()
            },
            ip_whitelist: IpCidrTable::new(),
            ip_blacklist: IpCidrTable::new(),
            host_gate: HostGate::new(),
        })
    }

    /// Parse + validate a YAML document. Returns a fully-validated snapshot or
    /// an actionable error (with `serde_yaml` line/column on parse failure).
    pub fn from_yaml_str(s: &str) -> anyhow::Result<Arc<Self>> {
        let config: AccessConfig = serde_yaml::from_str(s).context("parsing access-lists YAML")?;
        config.validate().context("validating access-lists")?;

        let mut ip_whitelist = IpCidrTable::new();
        for entry in &config.ip_whitelist {
            ip_whitelist
                .insert_str(entry)
                .with_context(|| format!("ip_whitelist entry {entry:?}"))?;
        }
        let mut ip_blacklist = IpCidrTable::new();
        for entry in &config.ip_blacklist {
            ip_blacklist
                .insert_str(entry)
                .with_context(|| format!("ip_blacklist entry {entry:?}"))?;
        }

        let mut host_gate = HostGate::new();
        for (tier, hosts) in &config.host_whitelist {
            for host in hosts {
                host_gate.insert(*tier, host);
            }
        }

        Ok(Arc::new(Self {
            config,
            ip_whitelist,
            ip_blacklist,
            host_gate,
        }))
    }

    /// Read + parse + validate a YAML file from disk.
    pub fn from_yaml_path(path: &Path) -> anyhow::Result<Arc<Self>> {
        let body = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::from_yaml_str(&body)
    }

    /// Borrowed view of the validated config — phases 02-04 build their
    /// runtime structures from this.
    #[must_use]
    pub const fn config(&self) -> &AccessConfig {
        &self.config
    }

    /// Per-tier whitelist mode lookup with safe default (`BlacklistOnly`).
    #[must_use]
    pub fn tier_mode(&self, tier: Tier) -> WhitelistMode {
        self.config.tier_whitelist_mode.get(&tier).copied().unwrap_or_default()
    }

    /// Whether this snapshot was loaded with `dry_run: true` — phase-04 uses
    /// this to log-but-not-block.
    #[must_use]
    pub const fn dry_run(&self) -> bool {
        self.config.dry_run
    }

    /// Pre-built IP whitelist trie. Hot-path lookup in phase-04.
    #[must_use]
    pub const fn ip_whitelist(&self) -> &IpCidrTable {
        &self.ip_whitelist
    }

    /// Pre-built IP blacklist trie. Hot-path lookup in phase-04.
    #[must_use]
    pub const fn ip_blacklist(&self) -> &IpCidrTable {
        &self.ip_blacklist
    }

    /// Pre-built per-tier Host allowlist. Hot-path lookup in phase-04.
    #[must_use]
    pub const fn host_gate(&self) -> &HostGate {
        &self.host_gate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_YAML: &str = r"
version: 1
ip_whitelist:
  - 10.0.0.0/8
  - 192.168.1.5
  - 2001:db8::/32
ip_blacklist:
  - 203.0.113.0/24
  - 198.51.100.42
host_whitelist:
  critical:
    - api.example.com
    - secure.example.com
  high:
    - api.example.com
  medium: []
  catch_all: []
tier_whitelist_mode:
  critical: blacklist_only
  high: blacklist_only
  medium: full_bypass
  catch_all: full_bypass
";

    #[test]
    fn parses_brainstorm_sample() {
        let lists = AccessLists::from_yaml_str(SAMPLE_YAML).expect("sample must parse");
        let cfg = lists.config();
        assert_eq!(cfg.ip_whitelist.len(), 3);
        assert_eq!(cfg.ip_blacklist.len(), 2);
        assert_eq!(cfg.host_whitelist.get(&Tier::Critical).map(Vec::len), Some(2));
        assert_eq!(lists.tier_mode(Tier::Medium), WhitelistMode::FullBypass);
    }

    #[test]
    fn missing_tier_mode_defaults_to_blacklist_only() {
        let yaml = "version: 1\n";
        let lists = AccessLists::from_yaml_str(yaml).expect("minimal yaml parses");
        assert_eq!(lists.tier_mode(Tier::Medium), WhitelistMode::BlacklistOnly);
    }

    #[test]
    fn rejects_unsupported_version() {
        let err = AccessLists::from_yaml_str("version: 2\n").expect_err("v2 must fail");
        assert!(format!("{err:#}").contains("version"));
    }

    #[test]
    fn rejects_invalid_cidr() {
        let yaml = "version: 1\nip_blacklist:\n  - not-a-cidr\n";
        let err = AccessLists::from_yaml_str(yaml).expect_err("bad CIDR must fail");
        assert!(format!("{err:#}").contains("ip_blacklist"));
    }

    #[test]
    fn rejects_host_with_port() {
        let yaml = "version: 1\nhost_whitelist:\n  critical:\n    - api.example.com:8080\n";
        let err = AccessLists::from_yaml_str(yaml).expect_err("port must fail");
        assert!(format!("{err:#}").contains("host_whitelist"));
    }

    #[test]
    fn rejects_uppercase_host() {
        let yaml = "version: 1\nhost_whitelist:\n  critical:\n    - API.example.com\n";
        let err = AccessLists::from_yaml_str(yaml).expect_err("uppercase must fail");
        assert!(format!("{err:#}").contains("lowercase"));
    }

    #[test]
    fn hard_cap_rejects_oversized_list() {
        // Build the AccessConfig directly: rendering 500_001 CIDRs through
        // serde_yaml is wasteful and we only need validate() to fire.
        let mut cfg = AccessConfig {
            version: SUPPORTED_VERSION,
            ..AccessConfig::default()
        };
        cfg.ip_blacklist = vec!["10.0.0.0/32".to_string(); HARD_REJECT_ENTRIES + 1];
        let err = cfg.validate().expect_err("must reject");
        assert!(format!("{err:#}").contains("hard cap"));
    }

    #[test]
    fn empty_returns_disabled_snapshot() {
        let lists = AccessLists::empty();
        assert!(lists.config().ip_whitelist.is_empty());
        assert!(!lists.dry_run());
    }
}
