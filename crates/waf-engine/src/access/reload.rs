//! FR-008 phase-06 — Access-list hot-reload watcher.
//!
//! Watches `rules/access-lists.yaml` and atomically `swap()`s the live
//! [`AccessLists`] snapshot on change. Mirrors `gateway::tiered::tier_config_watcher`
//! conventions (sync `std::thread` + `std::sync::mpsc`, parent-dir watch,
//! debounced reload, structured logging) so review surface stays small.
//!
//! Drop the returned [`AccessReloader`] to stop watching.
//!
//! Failure semantics (D8 / AC-07): any error in read → parse → validate →
//! build is logged at `warn` and the previous snapshot is retained. The
//! gateway never crashes from a bad config.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::{info, warn};

use crate::access::AccessLists;

/// Default debounce window. 250 ms covers typical editor save bursts
/// (truncate + write + chmod) per FR-002 precedent.
pub const DEFAULT_DEBOUNCE_MS: u64 = 250;

/// Errors returned synchronously from [`AccessReloader::spawn`]. Reload errors
/// happen on the background thread and are logged, not propagated.
#[derive(Debug)]
pub enum WatcherError {
    NoParent(PathBuf),
    NoFileName(PathBuf),
    Notify(notify::Error),
}

impl std::fmt::Display for WatcherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoParent(p) => write!(f, "config file has no parent directory: {}", p.display()),
            Self::NoFileName(p) => write!(f, "config file has no file name: {}", p.display()),
            Self::Notify(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for WatcherError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Notify(e) => Some(e),
            _ => None,
        }
    }
}

impl From<notify::Error> for WatcherError {
    fn from(e: notify::Error) -> Self {
        Self::Notify(e)
    }
}

/// Running file watcher. Drop to stop.
pub struct AccessReloader {
    // Notify watcher must outlive the reload thread — drop = stop watching.
    _watcher: RecommendedWatcher,
}

impl AccessReloader {
    /// Watch `path`'s parent directory and reload `store` on changes to that file.
    ///
    /// Watches the parent (not the file) so editors that rename-then-write —
    /// which replace the inode — are still observed.
    pub fn spawn(path: PathBuf, store: Arc<ArcSwap<AccessLists>>, debounce_ms: u64) -> Result<Self, WatcherError> {
        let parent = path
            .parent()
            .ok_or_else(|| WatcherError::NoParent(path.clone()))?
            .to_path_buf();
        let file_name = path
            .file_name()
            .ok_or_else(|| WatcherError::NoFileName(path.clone()))?
            .to_os_string();

        let (tx, rx) = std::sync::mpsc::channel::<notify::Result<Event>>();
        let mut watcher = RecommendedWatcher::new(tx, Config::default())?;
        watcher.watch(&parent, RecursiveMode::NonRecursive)?;
        info!(file = %path.display(), "access-lists hot-reload watching");

        let reload_path = path;
        std::thread::spawn(move || {
            let debounce = Duration::from_millis(debounce_ms);
            let mut last_event = Instant::now();
            let mut pending = false;

            loop {
                match rx.recv_timeout(debounce) {
                    Ok(Ok(event)) => {
                        let touches_us = event.paths.iter().any(|p| p.file_name() == Some(file_name.as_os_str()));
                        let relevant = matches!(
                            event.kind,
                            notify::EventKind::Create(_) | notify::EventKind::Modify(_) | notify::EventKind::Remove(_)
                        );
                        if touches_us && relevant {
                            last_event = Instant::now();
                            pending = true;
                        }
                    }
                    Ok(Err(e)) => warn!(error = %e, "access-lists watch error"),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        if pending && last_event.elapsed() >= debounce {
                            pending = false;
                            reload(&reload_path, &store);
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        info!("access-lists watcher channel closed; stopping");
                        break;
                    }
                }
            }
        });

        Ok(Self { _watcher: watcher })
    }
}

/// Read → parse → validate → build → swap. Logs at `warn` on failure;
/// previous snapshot is kept. Exposed so integration tests can drive the same
/// code path without racing the watcher's debounce window.
pub fn reload(path: &Path, store: &ArcSwap<AccessLists>) {
    match AccessLists::from_yaml_path(path) {
        Ok(new) => {
            store.store(new);
            info!(path = %path.display(), "access-lists reloaded");
        }
        Err(err) => {
            warn!(
                error = %err,
                path = %path.display(),
                "access-lists reload failed; keeping previous"
            );
        }
    }
}

/// SIGHUP listener (Unix only).
///
/// Spawns a tokio task that calls [`reload`] on every SIGHUP — same fail-soft
/// semantics. Caller must already be inside a tokio runtime; returns the task
/// handle so it can be aborted on shutdown.
#[cfg(unix)]
pub fn spawn_sighup_listener(
    path: PathBuf,
    store: Arc<ArcSwap<AccessLists>>,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sig = signal(SignalKind::hangup())?;
    Ok(tokio::spawn(async move {
        while sig.recv().await.is_some() {
            info!("SIGHUP received; reloading access-lists");
            reload(&path, &store);
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    #[test]
    fn t_watcher_error_display_no_parent() {
        let e = WatcherError::NoParent(PathBuf::from("/no-parent"));
        assert!(e.to_string().contains("no parent directory"));
        assert!(e.source().is_none());
    }

    #[test]
    fn t_watcher_error_display_no_file_name() {
        let e = WatcherError::NoFileName(PathBuf::from("/"));
        assert!(e.to_string().contains("no file name"));
        assert!(e.source().is_none());
    }

    #[test]
    fn t_watcher_error_from_notify_carries_source() {
        let notify_err = notify::Error::generic("synthetic");
        let e: WatcherError = notify_err.into();
        assert!(matches!(e, WatcherError::Notify(_)));
        assert!(e.source().is_some());
        // Display must not panic.
        let _ = e.to_string();
    }

    #[test]
    fn t_spawn_rejects_root_path() {
        // `/` has no parent → NoParent (Path::parent returns None for the root).
        let store = Arc::new(ArcSwap::from(AccessLists::empty()));
        match AccessReloader::spawn(PathBuf::from("/"), store, DEFAULT_DEBOUNCE_MS) {
            Err(WatcherError::NoParent(_)) => {}
            Ok(_) => panic!("root path should not succeed"),
            Err(other) => panic!("expected NoParent, got {other:?}"),
        }
    }

    #[test]
    fn t_reload_swaps_on_success() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let path = tmp.path().join("a.yaml");
        std::fs::write(&path, "version: 1\nip_blacklist:\n  - 203.0.113.0/24\n").expect("write");
        let store = Arc::new(ArcSwap::from(AccessLists::empty()));
        assert_eq!(store.load().config().ip_blacklist.len(), 0);
        reload(&path, &store);
        assert_eq!(store.load().config().ip_blacklist.len(), 1);
    }

    #[test]
    fn t_reload_keeps_prior_on_bad_yaml() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let path = tmp.path().join("a.yaml");
        std::fs::write(&path, "version: 1\nip_blacklist:\n  - 203.0.113.0/24\n").expect("write");
        let initial = AccessLists::from_yaml_path(&path).expect("v1");
        let store = Arc::new(ArcSwap::from(initial));
        let prior_ptr = Arc::as_ptr(&store.load_full());

        std::fs::write(&path, "version: 1\nip_blacklist:\n  - garbage\n").expect("write bad");
        reload(&path, &store);

        let now_ptr = Arc::as_ptr(&store.load_full());
        assert_eq!(prior_ptr, now_ptr, "snapshot must be retained on bad reload");
    }
}
