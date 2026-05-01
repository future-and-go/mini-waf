//! FR-007 phase-05 — Relay/proxy detection hot-reload watcher.
//!
//! Watches `rules/relay-detection.yaml`, the Tor exit list, and the ASN
//! data file, atomically swapping the corresponding [`ArcSwap`] snapshots
//! on change. Mirrors `access::reload::AccessReloader` conventions:
//! per-path sync `std::thread` + `std::sync::mpsc`, parent-dir watch,
//! debounced reload, fail-soft on parse/load error (D8 / AC-07 pattern).
//!
//! Drop the returned [`RelayReloader`] to stop watching. Refresh failures
//! are logged at `warn` and the previous snapshot is retained — the
//! gateway never crashes from a bad feed.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use arc_swap::ArcSwap;
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::{info, warn};

use crate::relay::config::RelayConfig;
use crate::relay::intel::AsnDb;
use crate::relay::intel::asn_feed::IpinfoLiteMmdb;
use crate::relay::intel::asn_feed_iptoasn::IptoasnTsv;
use crate::relay::providers::TorSet;
use crate::relay::providers::asn_classifier::SwapAsnDb;

/// 200ms covers typical editor save bursts (truncate + write + chmod).
pub const DEFAULT_DEBOUNCE_MS: u64 = 200;

/// Operator-owned files to watch. Each is optional — air-gapped or
/// disabled-feature deployments simply omit the path.
#[derive(Debug, Default, Clone)]
pub struct ReloadPaths {
    pub config_path: Option<PathBuf>,
    pub tor_list_path: Option<PathBuf>,
    pub asn_db_path: Option<PathBuf>,
}

/// Live `ArcSwap` pointers shared with the running detector + providers.
#[derive(Clone)]
pub struct ReloadSwaps {
    pub config: Arc<ArcSwap<RelayConfig>>,
    pub tor_set: Arc<ArcSwap<TorSet>>,
    pub asn_db: Arc<SwapAsnDb>,
}

/// ASN data file format. Picks the right loader on reload.
#[derive(Debug, Default, Clone, Copy)]
pub enum AsnFormat {
    #[default]
    IpinfoLiteMmdb,
    IptoasnTsv,
}

/// Running file watchers. Drop to stop all background reload threads.
pub struct RelayReloader {
    // notify watchers must outlive the reload thread — drop = stop watching.
    _watchers: Vec<RecommendedWatcher>,
}

impl RelayReloader {
    /// Spawn a watcher thread per `Some` path in `paths`.
    pub fn start(paths: ReloadPaths, swaps: &ReloadSwaps, asn_format: AsnFormat, debounce_ms: u64) -> Result<Self> {
        let mut watchers = Vec::new();
        if let Some(p) = paths.config_path {
            let store = Arc::clone(&swaps.config);
            watchers.push(spawn_watch(p, debounce_ms, move |path| reload_config(path, &store))?);
        }
        if let Some(p) = paths.tor_list_path {
            let store = Arc::clone(&swaps.tor_set);
            watchers.push(spawn_watch(p, debounce_ms, move |path| reload_tor(path, &store))?);
        }
        if let Some(p) = paths.asn_db_path {
            let store = Arc::clone(&swaps.asn_db);
            watchers.push(spawn_watch(p, debounce_ms, move |path| {
                reload_asn(path, &store, asn_format);
            })?);
        }
        Ok(Self { _watchers: watchers })
    }
}

/// Watch `path`'s parent directory and invoke `on_change(&path)` on
/// debounced create/modify/remove events touching the file name.
fn spawn_watch<F>(path: PathBuf, debounce_ms: u64, mut on_change: F) -> Result<RecommendedWatcher>
where
    F: FnMut(&Path) + Send + 'static,
{
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("relay watch path has no parent: {}", path.display()))?
        .to_path_buf();
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("relay watch path has no file name: {}", path.display()))?
        .to_os_string();

    let (tx, rx) = std::sync::mpsc::channel::<notify::Result<Event>>();
    let mut watcher = RecommendedWatcher::new(tx, Config::default())?;
    watcher.watch(&parent, RecursiveMode::NonRecursive)?;
    info!(file = %path.display(), "relay hot-reload watching");

    let reload_path = path;
    std::thread::spawn(move || {
        let debounce = Duration::from_millis(debounce_ms);
        let mut last_event = Instant::now();
        let mut pending = false;
        loop {
            match rx.recv_timeout(debounce) {
                Ok(Ok(event)) => {
                    let touches = event.paths.iter().any(|p| p.file_name() == Some(file_name.as_os_str()));
                    let relevant = matches!(
                        event.kind,
                        notify::EventKind::Create(_) | notify::EventKind::Modify(_) | notify::EventKind::Remove(_)
                    );
                    if touches && relevant {
                        last_event = Instant::now();
                        pending = true;
                    }
                }
                Ok(Err(e)) => warn!(error = %e, "relay watch error"),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if pending && last_event.elapsed() >= debounce {
                        pending = false;
                        on_change(&reload_path);
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    info!("relay watcher channel closed; stopping");
                    break;
                }
            }
        }
    });
    Ok(watcher)
}

/// Read → parse → validate → swap. Logs at `warn` on failure; previous
/// snapshot is kept. Exposed so integration tests can drive the same
/// path without racing the watcher's debounce window.
pub fn reload_config(path: &Path, store: &ArcSwap<RelayConfig>) {
    match RelayConfig::from_yaml_path(path) {
        Ok(new) => {
            store.store(new);
            info!(path = %path.display(), "relay config reloaded");
        }
        Err(err) => warn!(error = %err, path = %path.display(), "relay config reload failed; keeping previous"),
    }
}

pub fn reload_tor(path: &Path, store: &ArcSwap<TorSet>) {
    match TorSet::load(path) {
        Ok(new) => {
            store.store(Arc::new(new));
            info!(path = %path.display(), "tor exit list reloaded");
        }
        Err(err) => warn!(error = %err, path = %path.display(), "tor list reload failed; keeping previous"),
    }
}

pub fn reload_asn(path: &Path, store: &SwapAsnDb, fmt: AsnFormat) {
    let loaded: Result<Box<dyn AsnDb>> = match fmt {
        AsnFormat::IpinfoLiteMmdb => IpinfoLiteMmdb::open(path).map(|d| Box::new(d) as Box<dyn AsnDb>),
        AsnFormat::IptoasnTsv => IptoasnTsv::load(path).map(|d| Box::new(d) as Box<dyn AsnDb>),
    };
    match loaded {
        Ok(new) => {
            store.store(Arc::new(new));
            info!(path = %path.display(), "asn db reloaded");
        }
        Err(err) => warn!(error = %err, path = %path.display(), "asn db reload failed; keeping previous"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_reload_config_swaps_on_success() {
        let tmp = tempfile::tempdir().expect("tmp");
        let path = tmp.path().join("relay.yaml");
        std::fs::write(&path, "relay_detection:\n  max_chain_depth: 5\n").expect("write");
        let store = Arc::new(ArcSwap::from(Arc::new(RelayConfig::default())));
        reload_config(&path, &store);
        assert_eq!(store.load().max_chain_depth, 5);
    }

    #[test]
    fn t_reload_config_keeps_prior_on_bad_yaml() {
        let tmp = tempfile::tempdir().expect("tmp");
        let path = tmp.path().join("relay.yaml");
        std::fs::write(&path, "relay_detection:\n  max_chain_depth: 4\n").expect("write");
        let initial = RelayConfig::from_yaml_path(&path).expect("parse");
        let store = Arc::new(ArcSwap::from(initial));
        let prior = Arc::as_ptr(&store.load_full());
        // max_chain_depth: 0 fails validate() (must be >= 1).
        std::fs::write(&path, "relay_detection:\n  max_chain_depth: 0\n").expect("write bad");
        reload_config(&path, &store);
        let now = Arc::as_ptr(&store.load_full());
        assert_eq!(prior, now, "snapshot must be retained on bad reload");
    }

    #[test]
    fn t_reload_tor_swaps_on_success() {
        let tmp = tempfile::tempdir().expect("tmp");
        let path = tmp.path().join("tor.txt");
        std::fs::write(&path, "203.0.113.7\n").expect("write");
        let store = Arc::new(ArcSwap::from(Arc::new(TorSet::default())));
        reload_tor(&path, &store);
        assert_eq!(store.load().len(), 1);
    }

    #[test]
    fn t_watcher_propagates_config_edit_within_one_sec() {
        let tmp = tempfile::tempdir().expect("tmp");
        let path = tmp.path().join("relay.yaml");
        std::fs::write(&path, "relay_detection:\n  max_chain_depth: 2\n").expect("write");
        let cfg = RelayConfig::from_yaml_path(&path).expect("parse");
        let store = Arc::new(ArcSwap::from(cfg));
        let swaps = ReloadSwaps {
            config: Arc::clone(&store),
            tor_set: Arc::new(ArcSwap::from(Arc::new(TorSet::default()))),
            asn_db: Arc::new(ArcSwap::from_pointee(
                Box::new(crate::relay::intel::EmptyAsnDb) as Box<dyn AsnDb>
            )),
        };
        let _r = RelayReloader::start(
            ReloadPaths {
                config_path: Some(path.clone()),
                ..ReloadPaths::default()
            },
            &swaps,
            AsnFormat::default(),
            50,
        )
        .expect("start");
        std::fs::write(&path, "relay_detection:\n  max_chain_depth: 7\n").expect("write");
        // Poll up to 1s — debounce 50ms + filesystem event latency.
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            if store.load().max_chain_depth == 7 {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("config edit not propagated within 1s");
    }

    #[test]
    fn t_start_with_all_none_paths_succeeds() {
        let swaps = ReloadSwaps {
            config: Arc::new(ArcSwap::from(Arc::new(RelayConfig::default()))),
            tor_set: Arc::new(ArcSwap::from(Arc::new(TorSet::default()))),
            asn_db: Arc::new(ArcSwap::from_pointee(
                Box::new(crate::relay::intel::EmptyAsnDb) as Box<dyn AsnDb>
            )),
        };
        let r = RelayReloader::start(
            ReloadPaths::default(),
            &swaps,
            AsnFormat::default(),
            DEFAULT_DEBOUNCE_MS,
        )
        .expect("start");
        drop(r);
    }
}
