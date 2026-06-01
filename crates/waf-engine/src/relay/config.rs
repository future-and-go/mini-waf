//! FR-007 phase-01 — YAML schema + parser for `rules/relay-detection.yaml`.
//!
//! Mirrors the FR-008 access/config builder pattern: pure data + validation,
//! returning an `Arc<RelayConfig>` snapshot. No I/O of intel files, no
//! provider construction — those land in phases 02-04.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use ipnet::IpNet;
use regex::Regex;
use serde::{Deserialize, Serialize};

const HEADER_NAME_RE: &str = r"^[A-Za-z][A-Za-z0-9-]*$";

/// Top-level YAML wrapper.
///
/// `relay_detection:` is the single root key per brainstorm §4.6. Everything
/// else is optional → empty file parses to a "no signals enabled" snapshot
/// (D4 fail-open at config layer).
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelayDetectionDocument {
    #[serde(default)]
    pub relay_detection: RelayConfig,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RelayConfig {
    #[serde(default)]
    pub trusted_proxies: Vec<IpNet>,
    #[serde(default = "default_chain_depth")]
    pub max_chain_depth: u8,
    #[serde(default)]
    pub headers: HeaderConfig,
    #[serde(default)]
    pub asn: AsnConfig,
    #[serde(default)]
    pub tor: TorConfig,
    #[serde(default)]
    pub signals: SignalConfig,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            trusted_proxies: Vec::new(),
            max_chain_depth: default_chain_depth(),
            headers: HeaderConfig::default(),
            asn: AsnConfig::default(),
            tor: TorConfig::default(),
            signals: SignalConfig::default(),
        }
    }
}

const fn default_chain_depth() -> u8 {
    3
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HeaderConfig {
    #[serde(default = "default_xff_headers")]
    pub forwarded_for: Vec<String>,
}

impl Default for HeaderConfig {
    fn default() -> Self {
        Self {
            forwarded_for: default_xff_headers(),
        }
    }
}

fn default_xff_headers() -> Vec<String> {
    vec!["X-Forwarded-For".to_string(), "X-Real-IP".to_string()]
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct AsnConfig {
    /// `"ipinfo_lite"` (default mmdb), `"iptoasn"` (TSV fallback). When None
    /// and no `mmdb_path` is set, the classifier runs with `EmptyAsnDb`
    /// (every lookup → `AsnUnknown`).
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub mmdb_path: Option<PathBuf>,
    #[serde(default)]
    pub datacenter_lists: Vec<PathBuf>,
    #[serde(default)]
    pub refresh: Option<RefreshConfig>,
    /// When true, builder errors out if the configured ASN data source
    /// cannot be loaded. Default false → degrade to empty DB + warn.
    /// Operators flip this on for tiers where missing ASN data is itself
    /// a security failure (brainstorm §4.9 fail-close policy).
    #[serde(default)]
    pub fail_close: bool,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct TorConfig {
    #[serde(default)]
    pub list_path: Option<PathBuf>,
    #[serde(default)]
    pub refresh: Option<RefreshConfig>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct RefreshConfig {
    #[serde(default)]
    pub url: Option<String>,
    #[serde(
        default,
        deserialize_with = "deser_duration_opt",
        serialize_with = "ser_duration_opt"
    )]
    pub interval: Option<Duration>,
    #[serde(default)]
    pub etag: bool,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct SignalConfig {
    #[serde(default)]
    pub enabled: Vec<String>,
    #[serde(default)]
    pub risk_score_delta: HashMap<String, i32>,
}

impl RelayConfig {
    /// Syntactic + semantic checks. Provider construction is deferred — here
    /// we only ensure the file is well-formed.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.max_chain_depth < 1 {
            bail!("max_chain_depth must be >= 1, got {}", self.max_chain_depth);
        }

        let header_re = Regex::new(HEADER_NAME_RE).context("compiling header regex")?;
        for (idx, name) in self.headers.forwarded_for.iter().enumerate() {
            if !header_re.is_match(name) {
                bail!("headers.forwarded_for[{idx}] not a valid HTTP header name: {name:?}");
            }
        }

        let mut seen = HashSet::new();
        for (idx, sig) in self.signals.enabled.iter().enumerate() {
            if !seen.insert(sig.as_str()) {
                bail!("signals.enabled[{idx}] duplicate entry: {sig:?}");
            }
        }
        Ok(())
    }

    pub fn from_yaml_str(s: &str) -> anyhow::Result<Arc<Self>> {
        let doc: RelayDetectionDocument = serde_yaml::from_str(s).context("parsing relay-detection YAML")?;
        let cfg = doc.relay_detection;
        cfg.validate().context("validating relay-detection")?;
        Ok(Arc::new(cfg))
    }

    pub fn from_yaml_path(path: &Path) -> anyhow::Result<Arc<Self>> {
        let body = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::from_yaml_str(&body)
    }
}

#[allow(clippy::ref_option)]
fn ser_duration_opt<S>(dur: &Option<Duration>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match dur {
        None => s.serialize_none(),
        Some(d) => {
            let secs = d.as_secs();
            let millis = d.subsec_millis();
            let repr = if millis > 0 {
                format!("{}ms", secs * 1000 + u64::from(millis))
            } else if secs >= 3600 && secs % 3600 == 0 {
                format!("{}h", secs / 3600)
            } else if secs >= 60 && secs % 60 == 0 {
                format!("{}m", secs / 60)
            } else {
                format!("{secs}s")
            };
            s.serialize_str(&repr)
        }
    }
}

fn deser_duration_opt<'de, D>(d: D) -> Result<Option<Duration>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let s: Option<String> = Option::deserialize(d)?;
    s.map_or(Ok(None), |raw| parse_duration(&raw).map(Some).map_err(D::Error::custom))
}

fn parse_duration(raw: &str) -> Result<Duration, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("empty duration".to_string());
    }
    let (num_part, unit) = if let Some(rest) = s.strip_suffix("ms") {
        (rest, "ms")
    } else if let Some(rest) = s.strip_suffix('h') {
        (rest, "h")
    } else if let Some(rest) = s.strip_suffix('m') {
        (rest, "m")
    } else if let Some(rest) = s.strip_suffix('s') {
        (rest, "s")
    } else {
        return Err(format!("missing unit (h/m/s/ms) in {raw:?}"));
    };
    let n: u64 = num_part.parse().map_err(|_| format!("non-numeric duration {raw:?}"))?;
    match unit {
        "ms" => Ok(Duration::from_millis(n)),
        "s" => Ok(Duration::from_secs(n)),
        "m" => Ok(Duration::from_secs(n * 60)),
        "h" => Ok(Duration::from_secs(n * 3600)),
        other => Err(format!("unknown duration unit {other:?}")),
    }
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
