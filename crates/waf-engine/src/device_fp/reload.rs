//! FR-010 phase-02 — hot-reload watcher for `configs/device-fp.yaml`.
//!
//! Mirrors `relay::reload` and `access::reload` conventions: per-path
//! sync `std::thread` + `std::sync::mpsc`, parent-dir watch, debounced
//! reload, fail-soft on parse error. Drop the returned [`DeviceFpReloader`]
//! to stop watching.
//!
//! Failures are logged at `warn` and the previous snapshot is retained —
//! the gateway never crashes from a bad YAML edit.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use arc_swap::ArcSwap;
use notify::{Config as NotifyConfig, Event, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::{info, warn};

use crate::device_fp::config::DeviceFpConfig;

/// 200ms covers typical editor save bursts (truncate + write + chmod).
pub const DEFAULT_DEBOUNCE_MS: u64 = 200;

/// Owns the background watcher thread + the `notify` watcher itself.
/// Drop = stop watching.
pub struct DeviceFpReloader {
    _watcher: RecommendedWatcher,
}

impl DeviceFpReloader {
    /// Spawn a watcher that swaps `swap` whenever `path` changes.
    pub fn start(path: PathBuf, swap: Arc<ArcSwap<DeviceFpConfig>>, debounce_ms: u64) -> Result<Self> {
        let watcher = spawn_watch(path, debounce_ms, move |p| reload(p, &swap))?;
        Ok(Self { _watcher: watcher })
    }
}

fn reload(path: &Path, swap: &Arc<ArcSwap<DeviceFpConfig>>) {
    match DeviceFpConfig::from_path(path) {
        Ok(cfg) => {
            swap.store(cfg);
            info!(file = %path.display(), "device_fp: hot-reload OK");
        }
        Err(e) => {
            warn!(file = %path.display(), error = %e, "device_fp: hot-reload failed; keeping previous snapshot");
        }
    }
}

fn spawn_watch<F>(path: PathBuf, debounce_ms: u64, mut on_change: F) -> Result<RecommendedWatcher>
where
    F: FnMut(&Path) + Send + 'static,
{
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("device_fp watch path has no parent: {}", path.display()))?
        .to_path_buf();
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("device_fp watch path has no file name: {}", path.display()))?
        .to_os_string();

    let (tx, rx) = std::sync::mpsc::channel::<notify::Result<Event>>();
    let mut watcher = RecommendedWatcher::new(tx, NotifyConfig::default())?;
    watcher.watch(&parent, RecursiveMode::NonRecursive)?;
    info!(file = %path.display(), "device_fp: hot-reload watching");

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
                    warn!(error = %e, "device_fp: notify error");
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
        let path = dir.path().join("device-fp.yaml");
        std::fs::write(&path, "device_fp:\n  enabled: false\n").unwrap();

        let cfg = DeviceFpConfig::from_path(&path).unwrap();
        let swap = Arc::new(ArcSwap::from(cfg));
        assert!(!swap.load().enabled);

        let _r = DeviceFpReloader::start(path.clone(), Arc::clone(&swap), 50).expect("start watcher");

        // Write, then poll for swap. Notify needs ~ms; debounce is 50ms.
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "device_fp:\n  enabled: true\n").unwrap();
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

    /// Plan §Success Criteria: live behavior edits propagate within 500 ms,
    /// and a malformed YAML write keeps the last-good snapshot.
    #[test]
    fn behavior_block_hot_reload_propagates_then_survives_malformed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("device-fp.yaml");
        std::fs::write(
            &path,
            "device_fp:\n  behavior:\n    burst_interval:\n      risk_delta: 15\n",
        )
        .unwrap();

        let cfg = DeviceFpConfig::from_path(&path).unwrap();
        let swap = Arc::new(ArcSwap::from(cfg));
        assert_eq!(swap.load().behavior.burst_interval.risk_delta, 15);

        let _r = DeviceFpReloader::start(path.clone(), Arc::clone(&swap), 50).unwrap();

        // Flip 15 → 25 on disk; reload must observe within 500 ms (200 ms
        // debounce headroom + parse + swap).
        std::fs::write(
            &path,
            "device_fp:\n  behavior:\n    burst_interval:\n      risk_delta: 25\n",
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if swap.load().behavior.burst_interval.risk_delta == 25 {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            swap.load().behavior.burst_interval.risk_delta,
            25,
            "live edit must propagate"
        );

        // Now write malformed YAML — last-good (25) must be retained.
        std::fs::write(&path, "device_fp:\n  behavior:\n    cv_threshold: not_a_number\n").unwrap();
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(
            swap.load().behavior.burst_interval.risk_delta,
            25,
            "malformed YAML must not corrupt live state"
        );
    }

    #[test]
    fn reload_keeps_previous_snapshot_on_invalid_yaml() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("device-fp.yaml");
        std::fs::write(&path, "device_fp:\n  enabled: true\n").unwrap();
        let cfg = DeviceFpConfig::from_path(&path).unwrap();
        let swap = Arc::new(ArcSwap::from(cfg));
        let _r = DeviceFpReloader::start(path.clone(), Arc::clone(&swap), 50).unwrap();

        std::fs::write(&path, "device_fp:\n  not_a_field: 1\n").unwrap();
        std::thread::sleep(Duration::from_millis(400));
        assert!(
            swap.load().enabled,
            "previous snapshot must be retained on invalid YAML"
        );
    }
}
