//! FR-025 Phase 2: Hot-reload watcher for seed data files.
//!
//! Watches tor-exits.txt, asn-classes.csv, and risk-whitelist.txt for changes.
//! On any change, reloads all files and swaps `SeedTables` atomically.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use arc_swap::ArcSwap;
use notify::{Config as NotifyConfig, Event, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::{info, warn};

use super::tables::{SeedTables, SeedTablesBuilder};
use super::{asn, tor, whitelist};

/// Default debounce in milliseconds (500ms for atomic-rename pattern).
pub const DEFAULT_DEBOUNCE_MS: u64 = 500;

/// Paths to seed data files.
#[derive(Clone, Debug)]
pub struct SeedPaths {
    pub tor_exits: Option<PathBuf>,
    pub asn_classes: Option<PathBuf>,
    pub whitelist: Option<PathBuf>,
}

impl SeedPaths {
    /// Collect all existing paths for watching.
    fn existing_paths(&self) -> Vec<&Path> {
        [
            self.tor_exits.as_deref(),
            self.asn_classes.as_deref(),
            self.whitelist.as_deref(),
        ]
        .into_iter()
        .flatten()
        .filter(|p| p.exists())
        .collect()
    }

    /// Collect parent directories of all paths.
    fn parent_dirs(&self) -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        for path in [&self.tor_exits, &self.asn_classes, &self.whitelist]
            .into_iter()
            .flatten()
        {
            if let Some(parent) = path.parent()
                && !dirs.contains(&parent.to_path_buf())
            {
                dirs.push(parent.to_path_buf());
            }
        }
        dirs
    }
}

/// Owns the background watcher thread. Drop = stop watching.
pub struct SeedReloader {
    _watchers: Vec<RecommendedWatcher>,
}

impl SeedReloader {
    /// Spawn watchers for seed data files.
    #[allow(clippy::needless_pass_by_value)] // paths/swap moved into background threads
    pub fn start(paths: SeedPaths, swap: Arc<ArcSwap<SeedTables>>, debounce_ms: u64) -> Result<Self> {
        let parent_dirs = paths.parent_dirs();

        if parent_dirs.is_empty() {
            warn!("seed: no paths configured, hot-reload disabled");
            return Ok(Self { _watchers: vec![] });
        }

        let mut watchers = Vec::new();

        for dir in &parent_dirs {
            let watcher = spawn_dir_watch(dir.clone(), paths.clone(), Arc::clone(&swap), debounce_ms)?;
            watchers.push(watcher);
        }

        info!(dirs = ?parent_dirs, "seed: hot-reload watching");
        Ok(Self { _watchers: watchers })
    }
}

#[allow(clippy::needless_pass_by_value)] // values moved into spawned thread
fn spawn_dir_watch(
    dir: PathBuf,
    paths: SeedPaths,
    swap: Arc<ArcSwap<SeedTables>>,
    debounce_ms: u64,
) -> Result<RecommendedWatcher> {
    let (tx, rx) = std::sync::mpsc::channel::<notify::Result<Event>>();
    let mut watcher = RecommendedWatcher::new(tx, NotifyConfig::default())?;
    watcher.watch(&dir, RecursiveMode::NonRecursive)?;

    let watched_names: Vec<_> = paths
        .existing_paths()
        .into_iter()
        .filter_map(|p| p.file_name().map(std::ffi::OsStr::to_os_string))
        .collect();

    std::thread::spawn(move || {
        let debounce = Duration::from_millis(debounce_ms);
        let mut pending = false;
        let mut last_event = Instant::now();

        loop {
            match rx.recv_timeout(debounce) {
                Ok(Ok(event)) => {
                    let touches = event
                        .paths
                        .iter()
                        .any(|p| p.file_name().is_some_and(|n| watched_names.contains(&n.to_os_string())));
                    let relevant = matches!(
                        event.kind,
                        notify::EventKind::Create(_) | notify::EventKind::Modify(_) | notify::EventKind::Remove(_)
                    );
                    if touches && relevant {
                        last_event = Instant::now();
                        pending = true;
                    }
                }
                Ok(Err(e)) => {
                    warn!(error = %e, "seed: notify error");
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if pending && last_event.elapsed() >= debounce {
                        reload_all(&paths, &swap);
                        pending = false;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    });

    Ok(watcher)
}

fn reload_all(paths: &SeedPaths, swap: &Arc<ArcSwap<SeedTables>>) {
    let mut builder = SeedTablesBuilder::new();

    if let Some(ref path) = paths.tor_exits {
        for ip in tor::load_or_empty(path) {
            builder.add_tor_exit(ip);
        }
    }

    if let Some(ref path) = paths.asn_classes {
        let trie = asn::load_or_empty(path);
        for (network, (asn, class)) in trie.iter() {
            builder.add_asn_entry(network, *asn, *class);
        }
    }

    if let Some(ref path) = paths.whitelist {
        let trie = whitelist::load_or_empty(path);
        for (network, ()) in trie.iter() {
            builder.add_whitelist(network);
        }
    }

    swap.store(Arc::new(builder.build()));
    info!("seed: hot-reload complete");
}

/// Load seed tables from paths, returning empty on missing files.
pub fn load_tables(paths: &SeedPaths) -> SeedTables {
    let mut builder = SeedTablesBuilder::new();

    if let Some(ref path) = paths.tor_exits {
        for ip in tor::load_or_empty(path) {
            builder.add_tor_exit(ip);
        }
    }

    if let Some(ref path) = paths.asn_classes {
        let trie = asn::load_or_empty(path);
        for (network, (asn, class)) in trie.iter() {
            builder.add_asn_entry(network, *asn, *class);
        }
    }

    if let Some(ref path) = paths.whitelist {
        let trie = whitelist::load_or_empty(path);
        for (network, ()) in trie.iter() {
            builder.add_whitelist(network);
        }
    }

    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr};
    use tempfile::tempdir;

    #[test]
    fn load_tables_handles_missing_files() {
        let paths = SeedPaths {
            tor_exits: Some(PathBuf::from("/nonexistent/tor.txt")),
            asn_classes: None,
            whitelist: None,
        };

        let tables = load_tables(&paths);
        assert!(!tables.is_tor_exit(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }

    #[test]
    fn load_tables_from_files() {
        let dir = tempdir().unwrap();

        let tor_path = dir.path().join("tor-exits.txt");
        let mut f = std::fs::File::create(&tor_path).unwrap();
        writeln!(f, "1.2.3.4").unwrap();
        drop(f);

        let whitelist_path = dir.path().join("whitelist.txt");
        let mut f = std::fs::File::create(&whitelist_path).unwrap();
        writeln!(f, "10.0.0.0/8").unwrap();
        drop(f);

        let paths = SeedPaths {
            tor_exits: Some(tor_path),
            asn_classes: None,
            whitelist: Some(whitelist_path),
        };

        let tables = load_tables(&paths);
        assert!(tables.is_tor_exit(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert!(tables.is_whitelisted(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
    }

    #[test]
    fn hot_reload_swaps_on_file_change() {
        let dir = tempdir().unwrap();
        let tor_path = dir.path().join("tor-exits.txt");
        std::fs::write(&tor_path, "").unwrap();

        let paths = SeedPaths {
            tor_exits: Some(tor_path.clone()),
            asn_classes: None,
            whitelist: None,
        };

        let tables = load_tables(&paths);
        let swap = Arc::new(ArcSwap::from(Arc::new(tables)));

        assert!(!swap.load().is_tor_exit(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));

        let _r = SeedReloader::start(paths, Arc::clone(&swap), 100).unwrap();

        let mut f = std::fs::File::create(&tor_path).unwrap();
        writeln!(f, "1.2.3.4").unwrap();
        f.sync_all().unwrap();
        drop(f);

        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if swap.load().is_tor_exit(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("hot reload never observed new tor exit");
    }
}
