//! FR-004 phase-07 — hot-reload watcher for `configs/rate-limit.yaml`.
//!
//! Mirrors `device_fp::reload`: parent-dir `notify` watcher on a sync
//! `std::thread`, debounced, fail-soft on parse error (previous snapshot
//! retained). Drop the returned [`RateLimitReloader`] to stop watching.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use arc_swap::ArcSwap;
use notify::{Config as NotifyConfig, Event, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::{info, warn};

use super::RateLimitConfig;
use super::config::RateLimitFileConfig;

/// 200 ms covers typical editor save bursts (truncate + write + chmod).
pub const DEFAULT_DEBOUNCE_MS: u64 = 200;

/// Owns the background watcher thread + the `notify` watcher itself.
/// Drop = stop watching.
pub struct RateLimitReloader {
    _watcher: RecommendedWatcher,
}

impl RateLimitReloader {
    /// Spawn a watcher that swaps `swap` whenever `path` changes.
    pub fn start(path: PathBuf, swap: Arc<ArcSwap<RateLimitConfig>>, debounce_ms: u64) -> Result<Self> {
        let watcher = spawn_watch(path, debounce_ms, move |p| reload(p, &swap))?;
        Ok(Self { _watcher: watcher })
    }
}

fn reload(path: &Path, swap: &Arc<ArcSwap<RateLimitConfig>>) {
    match RateLimitFileConfig::from_path(path) {
        Ok(cfg) => {
            swap.store(cfg);
            info!(file = %path.display(), "rate_limit: hot-reload OK");
        }
        Err(e) => {
            warn!(
                file = %path.display(),
                error = %e,
                "rate_limit: hot-reload failed; keeping previous snapshot"
            );
        }
    }
}

fn spawn_watch<F>(path: PathBuf, debounce_ms: u64, mut on_change: F) -> Result<RecommendedWatcher>
where
    F: FnMut(&Path) + Send + 'static,
{
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("rate_limit watch path has no parent: {}", path.display()))?
        .to_path_buf();
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("rate_limit watch path has no file name: {}", path.display()))?
        .to_os_string();

    let (tx, rx) = std::sync::mpsc::channel::<notify::Result<Event>>();
    let mut watcher = RecommendedWatcher::new(tx, NotifyConfig::default())?;
    watcher.watch(&parent, RecursiveMode::NonRecursive)?;
    info!(file = %path.display(), "rate_limit: hot-reload watching");

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
                        pending = true;
                        last_event = Instant::now();
                    }
                }
                Ok(Err(e)) => warn!(error = %e, "rate_limit: notify channel error"),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
            if pending && last_event.elapsed() >= debounce {
                on_change(&reload_path);
                pending = false;
            }
        }
    });

    Ok(watcher)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::Duration;

    fn write_file(path: &Path, contents: &str) {
        let mut f = std::fs::File::create(path).expect("create");
        f.write_all(contents.as_bytes()).expect("write");
        f.sync_all().expect("sync");
    }

    /// End-to-end: writing a new YAML file flips the live config snapshot.
    #[test]
    fn hot_reload_swaps_snapshot() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("rate-limit.yaml");

        write_file(
            &path,
            r"
rate_limit:
  enabled: true
  session_cookie: SID1
  tiers:
    catch_all:
      burst_capacity: 1
      burst_refill_per_s: 0.0
      window_secs: 60
      window_limit: 100
",
        );
        let initial = RateLimitFileConfig::from_path(&path).expect("initial parse");
        assert_eq!(initial.session_cookie, "SID1");
        let swap = Arc::new(ArcSwap::from(initial));

        let _reloader = RateLimitReloader::start(path.clone(), Arc::clone(&swap), 50).expect("start");

        // Write a new config — snapshot should swap within debounce + slack.
        std::thread::sleep(Duration::from_millis(50));
        write_file(
            &path,
            r"
rate_limit:
  enabled: true
  session_cookie: SID2
  tiers:
    catch_all:
      burst_capacity: 9
      burst_refill_per_s: 0.0
      window_secs: 60
      window_limit: 100
",
        );

        // Poll up to 3s for the swap.
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if swap.load().session_cookie == "SID2" {
                break;
            }
            assert!(Instant::now() < deadline, "hot-reload did not swap within 3s");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Bad YAML retains the previous snapshot — no panic, no crash.
    #[test]
    fn bad_yaml_retains_previous_snapshot() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("rate-limit.yaml");

        write_file(
            &path,
            r"
rate_limit:
  enabled: true
  session_cookie: GOOD
",
        );
        let initial = RateLimitFileConfig::from_path(&path).expect("initial parse");
        let swap = Arc::new(ArcSwap::from(initial));

        let _reloader = RateLimitReloader::start(path.clone(), Arc::clone(&swap), 50).expect("start");

        std::thread::sleep(Duration::from_millis(50));
        write_file(&path, "rate_limit:\n  bogus_field: 1\n");

        // Wait long enough that any swap would have happened.
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(
            swap.load().session_cookie,
            "GOOD",
            "previous snapshot must be retained on parse error"
        );
    }
}
