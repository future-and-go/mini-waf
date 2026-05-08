//! FR-025 hot-reload watcher for `configs/risk.yaml`.
//!
//! Mirrors `device_fp::reload` pattern: per-path sync thread + mpsc, parent-dir
//! watch, debounced reload, fail-soft on parse error.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use arc_swap::ArcSwap;
use notify::{Config as NotifyConfig, Event, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::{info, warn};

use crate::risk::config::RiskConfig;

/// Default debounce in milliseconds.
pub const DEFAULT_DEBOUNCE_MS: u64 = 200;

/// Owns the background watcher thread. Drop = stop watching.
pub struct RiskReloader {
    _watcher: RecommendedWatcher,
}

impl RiskReloader {
    /// Spawn a watcher that swaps `swap` whenever `path` changes.
    pub fn start(path: PathBuf, swap: Arc<ArcSwap<RiskConfig>>, debounce_ms: u64) -> Result<Self> {
        let watcher = spawn_watch(path, debounce_ms, move |p| reload(p, &swap))?;
        Ok(Self { _watcher: watcher })
    }
}

fn reload(path: &Path, swap: &Arc<ArcSwap<RiskConfig>>) {
    match RiskConfig::from_path(path) {
        Ok(cfg) => {
            swap.store(cfg);
            info!(file = %path.display(), "risk: hot-reload OK");
        }
        Err(e) => {
            warn!(file = %path.display(), error = %e, "risk: hot-reload failed; keeping previous snapshot");
        }
    }
}

fn spawn_watch<F>(path: PathBuf, debounce_ms: u64, mut on_change: F) -> Result<RecommendedWatcher>
where
    F: FnMut(&Path) + Send + 'static,
{
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("risk watch path has no parent: {}", path.display()))?
        .to_path_buf();
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("risk watch path has no file name: {}", path.display()))?
        .to_os_string();

    let (tx, rx) = std::sync::mpsc::channel::<notify::Result<Event>>();
    let mut watcher = RecommendedWatcher::new(tx, NotifyConfig::default())?;
    watcher.watch(&parent, RecursiveMode::NonRecursive)?;
    info!(file = %path.display(), "risk: hot-reload watching");

    let reload_path = path;
    std::thread::spawn(move || {
        let debounce = Duration::from_millis(debounce_ms);
        let mut pending = false;
        let mut last_event = Instant::now();
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
                Ok(Err(e)) => {
                    warn!(error = %e, "risk: notify error");
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if pending && last_event.elapsed() >= debounce {
                        on_change(&reload_path);
                        pending = false;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    });

    Ok(watcher)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn reload_swaps_snapshot_on_file_change() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("risk.yaml");
        std::fs::write(&path, "risk:\n  enabled: false\n").unwrap();

        let cfg = RiskConfig::from_path(&path).unwrap();
        let swap = Arc::new(ArcSwap::from(cfg));
        assert!(!swap.load().enabled);

        let _r = RiskReloader::start(path.clone(), Arc::clone(&swap), 50).expect("start watcher");

        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "risk:\n  enabled: true\n").unwrap();
        f.sync_all().unwrap();
        drop(f);

        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if swap.load().enabled {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("hot reload never observed enabled=true");
    }

    #[test]
    fn reload_keeps_previous_on_invalid_yaml() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("risk.yaml");
        std::fs::write(&path, "risk:\n  enabled: true\n").unwrap();

        let cfg = RiskConfig::from_path(&path).unwrap();
        let swap = Arc::new(ArcSwap::from(cfg));
        let _r = RiskReloader::start(path.clone(), Arc::clone(&swap), 50).unwrap();

        // Write malformed YAML (ttl_secs expects a number, not a string)
        std::fs::write(&path, "risk:\n  ttl_secs: not_a_number\n").unwrap();
        std::thread::sleep(Duration::from_millis(400));

        assert!(
            swap.load().enabled,
            "previous snapshot must be retained on invalid YAML"
        );
    }
}
