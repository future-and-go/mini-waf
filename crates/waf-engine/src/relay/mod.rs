//! FR-007 — Relay / proxy detection subsystem.
//!
//! Phase-01 wires only the public data model, traits, YAML parser, and a
//! `RelayDetector` facade stub returning a minimal `ClientIdentity`.
//! Phases 02-04 register concrete `SignalProvider`s; phase-05 adds reload.

pub mod config;
pub mod intel;
pub mod providers;
pub mod registry;
pub mod reload;
pub mod signal;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use http::HeaderMap;
use tokio::task::JoinHandle;

pub use config::{
    AsnConfig, HeaderConfig, RefreshConfig, RelayConfig, RelayDetectionDocument, SignalConfig, TorConfig,
};
pub use intel::{AsnDb, AsnRecord, DatacenterSet, EmptyAsnDb, IntelProvider, RefreshOutcome};
pub use registry::ProviderRegistry;
pub use signal::{AsnClass, ClientIdentity, RelayCtx, Signal, SignalProvider};

/// Per-feed metadata for the admin Threat-Intel panel (FR-042 / FR-008, D3).
///
/// Reflects the on-disk intel feeds configured in `relay.yaml`. Metadata-only:
/// never carries the raw IP / ASN lists (those would leak detection coverage).
#[derive(Clone, Debug, serde::Serialize)]
pub struct FeedMeta {
    /// Stable feed key: `tor_exit` | `asn` | `datacenter`.
    pub name: String,
    /// Configured source path (or `(not configured)`).
    pub source: String,
    /// Loaded entry count (0 when the feed is unconfigured or count is not
    /// cheaply available, e.g. an ASN mmdb).
    pub entry_count: u64,
    /// Last load/refresh time (source-file mtime, epoch ms; 0 when unknown).
    pub last_refresh_ms: i64,
    /// Whether the corresponding provider is in `signals.enabled`.
    pub enabled: bool,
}

fn file_mtime_ms(path: &std::path::Path) -> i64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

/// Build the threat-intel feed metadata list from a validated [`RelayConfig`].
///
/// Loads each configured feed file to count entries; an unconfigured or
/// failing feed yields a zero-count row rather than an error (fail-soft).
#[must_use]
pub fn load_feed_metadata(cfg: &RelayConfig) -> Vec<FeedMeta> {
    use crate::relay::providers::TorSet;

    let enabled_has = |name: &str| cfg.signals.enabled.iter().any(|s| s == name);
    let mut feeds = Vec::with_capacity(3);

    // Tor exit list.
    let tor = cfg.tor.list_path.as_ref().map_or_else(
        || FeedMeta {
            name: "tor_exit".to_string(),
            source: "(not configured)".to_string(),
            entry_count: 0,
            last_refresh_ms: 0,
            enabled: enabled_has("tor_exit"),
        },
        |p| {
            let count = TorSet::load(p).map_or(0, |s| u64::try_from(s.len()).unwrap_or(u64::MAX));
            FeedMeta {
                name: "tor_exit".to_string(),
                source: p.display().to_string(),
                entry_count: count,
                last_refresh_ms: file_mtime_ms(p),
                enabled: enabled_has("tor_exit"),
            }
        },
    );
    feeds.push(tor);

    // ASN database (mmdb / TSV). Entry count is not cheaply available from an
    // mmdb reader, so report the configured source + mtime with a 0 count.
    let asn_enabled = enabled_has("asn_classifier");
    let asn = cfg.asn.mmdb_path.as_ref().map_or_else(
        || FeedMeta {
            name: "asn".to_string(),
            source: "(not configured)".to_string(),
            entry_count: 0,
            last_refresh_ms: 0,
            enabled: asn_enabled,
        },
        |p| FeedMeta {
            name: "asn".to_string(),
            source: p.display().to_string(),
            entry_count: 0,
            last_refresh_ms: file_mtime_ms(p),
            enabled: asn_enabled,
        },
    );
    feeds.push(asn);

    // Datacenter override lists (one or more files merged).
    let datacenter = if cfg.asn.datacenter_lists.is_empty() {
        FeedMeta {
            name: "datacenter".to_string(),
            source: "(not configured)".to_string(),
            entry_count: 0,
            last_refresh_ms: 0,
            enabled: asn_enabled,
        }
    } else {
        let count = DatacenterSet::load(&cfg.asn.datacenter_lists).map_or(0, |s| {
            u64::try_from(s.asn_ids.len() + s.operator_allow.len() + s.operator_deny.len()).unwrap_or(u64::MAX)
        });
        let refreshed = cfg
            .asn
            .datacenter_lists
            .iter()
            .map(|p| file_mtime_ms(p))
            .max()
            .unwrap_or(0);
        let source = cfg
            .asn
            .datacenter_lists
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        FeedMeta {
            name: "datacenter".to_string(),
            source,
            entry_count: count,
            last_refresh_ms: refreshed,
            enabled: asn_enabled,
        }
    };
    feeds.push(datacenter);

    feeds
}

/// Top-level facade. Owns the active config snapshot + provider registry.
/// Hot-swap of `cfg` is via `ArcSwap` (phase-05); registry is rebuilt on
/// reload, not mutated in place.
pub struct RelayDetector {
    cfg: Arc<ArcSwap<RelayConfig>>,
    registry: ProviderRegistry,
}

impl RelayDetector {
    #[must_use]
    pub fn new(cfg: Arc<RelayConfig>, registry: ProviderRegistry) -> Self {
        Self {
            cfg: Arc::new(ArcSwap::from(cfg)),
            registry,
        }
    }

    /// Empty detector — used at boot before YAML loads, or on degraded
    /// startup. Emits no signals (fail-open at config layer).
    #[must_use]
    pub fn empty() -> Self {
        Self::new(Arc::new(RelayConfig::default()), ProviderRegistry::new())
    }

    #[must_use]
    pub fn config(&self) -> Arc<RelayConfig> {
        self.cfg.load_full()
    }

    /// Spawn one background refresh loop per supplied intel provider.
    ///
    /// Caller owns the returned handles — drop or `abort()` to stop a
    /// loop. Each loop survives transient `Failed` outcomes (logs + waits
    /// for next interval); only a panic in the provider would terminate
    /// the loop, which `tokio` reports via the `JoinHandle`.
    ///
    /// Phase-04 ships the spawn primitive; phase-05's watcher decides
    /// which providers are active.
    pub fn start_refresh_tasks(providers: Vec<(Arc<dyn IntelProvider>, Duration)>) -> Vec<JoinHandle<()>> {
        providers
            .into_iter()
            .map(|(provider, interval)| {
                tokio::spawn(async move {
                    intel_refresh_loop(provider, interval).await;
                })
            })
            .collect()
    }

    /// Phase-01 stub: returns `peer_ip` with `AsnClass::Unknown` plus whatever
    /// signals the (empty) registry produces. Phases 02-04 enrich this.
    pub fn evaluate(&self, peer_ip: IpAddr, headers: &HeaderMap) -> ClientIdentity {
        let ctx = RelayCtx::new(peer_ip, headers, Instant::now());
        let signals = self.registry.dispatch(&ctx);
        let real_ip = ctx.derived().map_or(peer_ip, |d| d.real_ip);
        ClientIdentity {
            real_ip,
            asn: None,
            asn_class: AsnClass::Unknown,
            signals,
        }
    }
}

/// Periodic refresh: one tick per `interval`, log + retain on failure.
async fn intel_refresh_loop(provider: Arc<dyn IntelProvider>, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    // Skip the immediate first tick — boot loaders already do an eager
    // load; first refresh fires after `interval` elapses.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        match provider.refresh().await {
            Ok(RefreshOutcome::Updated) => {
                tracing::info!(provider = provider.name(), "intel updated");
            }
            Ok(RefreshOutcome::NotModified) => {}
            Ok(RefreshOutcome::Failed(e)) => {
                tracing::warn!(provider = provider.name(), error = %e, "intel refresh failed; retaining last good");
            }
            Err(e) => {
                tracing::warn!(provider = provider.name(), error = %e, "intel refresh hard error");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn load_feed_metadata_empty_config_lists_three_disabled_feeds() {
        let cfg = RelayConfig::default();
        let feeds = super::load_feed_metadata(&cfg);
        assert_eq!(feeds.len(), 3, "tor_exit + asn + datacenter");
        let names: Vec<&str> = feeds.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"tor_exit"));
        assert!(names.contains(&"asn"));
        assert!(names.contains(&"datacenter"));
        for f in &feeds {
            assert!(!f.enabled, "default config enables nothing");
            assert_eq!(f.entry_count, 0);
            assert_eq!(f.source, "(not configured)");
        }
    }

    #[test]
    fn load_feed_metadata_marks_enabled_from_signals() {
        let yaml = r#"
relay_detection:
  signals:
    enabled: ["tor_exit", "asn_classifier"]
"#;
        let cfg = RelayConfig::from_yaml_str(yaml).expect("parse");
        let feeds = super::load_feed_metadata(&cfg);
        let tor = feeds.iter().find(|f| f.name == "tor_exit").expect("tor feed");
        let asn = feeds.iter().find(|f| f.name == "asn").expect("asn feed");
        assert!(tor.enabled, "tor_exit in signals.enabled");
        assert!(asn.enabled, "asn_classifier in signals.enabled");
    }

    #[test]
    fn empty_detector_yields_unknown_identity() {
        let det = RelayDetector::empty();
        let headers = HeaderMap::new();
        let id = det.evaluate(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), &headers);
        assert_eq!(id.asn_class, AsnClass::Unknown);
        assert!(id.signals.is_empty());
        assert!(id.asn.is_none());
    }

    #[test]
    fn file_mtime_ms_is_zero_for_missing_file_and_positive_for_real_file() {
        assert_eq!(super::file_mtime_ms(std::path::Path::new("/nonexistent/feed.txt")), 0);
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("feed.txt");
        std::fs::write(&path, "1.2.3.4\n").expect("write");
        assert!(super::file_mtime_ms(&path) > 0);
    }

    #[test]
    fn load_feed_metadata_counts_entries_from_configured_files() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let tor_path = tmp.path().join("tor-exits.txt");
        std::fs::write(&tor_path, "# comment\n\n1.2.3.4\n5.6.7.8\nnot-an-ip\n").expect("write tor");
        let mmdb_path = tmp.path().join("asn.mmdb");
        std::fs::write(&mmdb_path, "opaque").expect("write mmdb");
        let dc_path = tmp.path().join("datacenters.txt");
        std::fs::write(&dc_path, "13335\n16509 # aws\n").expect("write dc");

        let mut cfg = RelayConfig::default();
        cfg.tor.list_path = Some(tor_path.clone());
        cfg.asn.mmdb_path = Some(mmdb_path.clone());
        cfg.asn.datacenter_lists = vec![dc_path.clone()];

        let feeds = super::load_feed_metadata(&cfg);
        let tor = feeds.iter().find(|f| f.name == "tor_exit").expect("tor feed");
        assert_eq!(tor.entry_count, 2, "comments/blank/malformed lines skipped");
        assert_eq!(tor.source, tor_path.display().to_string());
        assert!(tor.last_refresh_ms > 0);

        let asn = feeds.iter().find(|f| f.name == "asn").expect("asn feed");
        assert_eq!(asn.entry_count, 0, "mmdb entry count is not cheaply available");
        assert_eq!(asn.source, mmdb_path.display().to_string());
        assert!(asn.last_refresh_ms > 0);

        let dc = feeds.iter().find(|f| f.name == "datacenter").expect("dc feed");
        assert_eq!(dc.entry_count, 2);
        assert_eq!(dc.source, dc_path.display().to_string());
        assert!(dc.last_refresh_ms > 0);
    }

    #[test]
    fn load_feed_metadata_is_fail_soft_for_unreadable_feed_files() {
        let mut cfg = RelayConfig::default();
        cfg.tor.list_path = Some(std::path::PathBuf::from("/nonexistent/tor.txt"));
        cfg.asn.datacenter_lists = vec![std::path::PathBuf::from("/nonexistent/dc.txt")];

        let feeds = super::load_feed_metadata(&cfg);
        let tor = feeds.iter().find(|f| f.name == "tor_exit").expect("tor feed");
        assert_eq!(tor.entry_count, 0);
        assert_eq!(tor.last_refresh_ms, 0);
        assert_eq!(tor.source, "/nonexistent/tor.txt");

        let dc = feeds.iter().find(|f| f.name == "datacenter").expect("dc feed");
        assert_eq!(dc.entry_count, 0);
        assert_eq!(dc.last_refresh_ms, 0);
    }

    #[derive(Default)]
    struct ScriptedProvider {
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl IntelProvider for ScriptedProvider {
        fn name(&self) -> &'static str {
            "scripted"
        }

        async fn refresh(&self) -> anyhow::Result<RefreshOutcome> {
            let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            match n {
                0 => Ok(RefreshOutcome::Updated),
                1 => Ok(RefreshOutcome::NotModified),
                2 => Ok(RefreshOutcome::Failed(anyhow::anyhow!("transient"))),
                _ => Err(anyhow::anyhow!("hard error")),
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn refresh_loop_survives_every_outcome_kind() {
        let provider = Arc::new(ScriptedProvider::default());
        let handles = RelayDetector::start_refresh_tasks(vec![(
            provider.clone() as Arc<dyn IntelProvider>,
            Duration::from_millis(10),
        )]);

        // Paused-clock advance: each step fires at most one interval tick.
        // The loop must keep running through Updated, NotModified, Failed,
        // and hard-Err outcomes rather than terminating.
        for _ in 0..200 {
            if provider.calls.load(std::sync::atomic::Ordering::SeqCst) >= 5 {
                break;
            }
            tokio::time::advance(Duration::from_millis(10)).await;
            tokio::task::yield_now().await;
        }
        assert!(
            provider.calls.load(std::sync::atomic::Ordering::SeqCst) >= 5,
            "refresh loop stopped early"
        );
        for h in handles {
            h.abort();
        }
    }
}
