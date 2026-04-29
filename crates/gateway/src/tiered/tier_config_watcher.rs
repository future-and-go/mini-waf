//! Tier config hot-reload — watch a TOML file and `swap()` the registry on change.
//!
//! Mirrors the `std::thread` + sync `mpsc` pattern from `waf_engine::rules::hot_reload`.
//! Drop the returned `TierConfigWatcher` to stop watching.
//!
//! Design notes:
//! - Watch the *parent directory* (not the file). Editors that rename-then-write
//!   replace the inode; watching the file directly drops the new file silently.
//!   We filter events by file name to ignore noise from sibling files.
//! - Debounce by waiting `debounce_ms` after the last event before reloading —
//!   editors emit 2-3 events per save (truncate, write, chmod).
//! - Any error in the reload chain (read / parse / validate / compile) is logged
//!   at `warn` and the current snapshot is kept. Never panic on bad config.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use serde::Deserialize;
use tracing::{info, warn};
use waf_common::tier::TierConfig;

use crate::tiered::tier_policy_registry::{TierPolicyRegistry, TierSnapshot};

/// Default debounce window. 200ms covers typical editor save bursts.
pub const DEFAULT_DEBOUNCE_MS: u64 = 200;

/// Errors returned synchronously from `spawn()`. Reload errors happen on the
/// background thread and are logged, not propagated.
#[derive(Debug, thiserror::Error)]
pub enum WatcherError {
    #[error("config file has no parent directory: {0}")]
    NoParent(PathBuf),
    #[error("config file has no file name: {0}")]
    NoFileName(PathBuf),
    #[error(transparent)]
    Notify(#[from] notify::Error),
}

/// TOML wrapper so editing other tables in the same file does NOT false-fail
/// the tier reload. Missing `[tiered_protection]` → log warn, keep previous.
#[derive(Debug, Deserialize)]
struct TomlEnvelope {
    #[serde(default)]
    tiered_protection: Option<TierConfig>,
}

/// Running file watcher. Drop to stop.
pub struct TierConfigWatcher {
    // Notify watcher must be kept alive — drop = stop watching.
    _watcher: RecommendedWatcher,
}

impl TierConfigWatcher {
    /// Watch `path`'s parent directory and reload `registry` on changes to that file.
    pub fn spawn(path: PathBuf, registry: Arc<TierPolicyRegistry>, debounce_ms: u64) -> Result<Self, WatcherError> {
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
        info!(file = %path.display(), "tier config hot-reload watching");

        let reload_path = path;
        std::thread::spawn(move || {
            let debounce = Duration::from_millis(debounce_ms);
            let mut last_event = Instant::now();
            let mut pending = false;

            loop {
                match rx.recv_timeout(debounce) {
                    Ok(Ok(event)) => {
                        // Only react to events naming our config file.
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
                    Ok(Err(e)) => warn!(error = %e, "tier config watch error"),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        if pending && last_event.elapsed() >= debounce {
                            pending = false;
                            reload(&reload_path, &registry);
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        info!("tier config watcher channel closed; stopping");
                        break;
                    }
                }
            }
        });

        Ok(Self { _watcher: watcher })
    }
}

/// Read → parse → validate → compile → swap. Logs at warn on any failure;
/// never panics. Exposed so the integration test can drive the same code
/// path without racing the file watcher's debounce.
pub fn reload(path: &Path, registry: &TierPolicyRegistry) {
    match try_reload(path) {
        Ok(snap) => {
            let rule_count = snap.classifier.rule_count();
            let tier_count = snap.policies.len();
            registry.swap(snap);
            info!(rule_count, tier_count, "tier config reloaded");
        }
        Err(err) => {
            warn!(error = %err, path = %path.display(), "tier config reload failed; keeping previous");
        }
    }
}

fn try_reload(path: &Path) -> anyhow::Result<TierSnapshot> {
    let raw = std::fs::read_to_string(path)?;
    let env: TomlEnvelope = toml::from_str(&raw)?;
    let cfg = env
        .tiered_protection
        .ok_or_else(|| anyhow::anyhow!("[tiered_protection] table missing"))?;
    Ok(TierSnapshot::try_from_config(cfg)?)
}
