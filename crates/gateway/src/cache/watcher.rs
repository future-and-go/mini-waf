//! `rules/cache.yaml` hot-reload watcher.
//!
//! Same pattern as `tiered::tier_config_watcher`: watch the *parent directory*
//! (not the file inode — editors that rename-then-write break inode-watching),
//! debounce a burst of save events, then atomically swap the compiled ruleset.
//!
//! Failure modes by stage:
//! - Boot (`load_or_empty`): missing file → empty set + warn; bad YAML → fail-fast.
//! - Reload (this watcher): any error → keep prior + warn. Never panic.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::{info, warn};

use crate::cache::config::CacheConfigDoc;
use crate::cache::rule_set::{CompiledRuleSet, RuleSetHolder};

/// Default debounce window. 200ms covers typical editor save bursts.
pub const DEFAULT_DEBOUNCE_MS: u64 = 200;

/// Errors returned synchronously from `spawn()`. Reload errors stay on the
/// background thread (logged, not propagated) so a bad save never tears down
/// the proxy.
#[derive(Debug, thiserror::Error)]
pub enum CacheWatcherError {
    #[error("config file has no parent directory: {0}")]
    NoParent(PathBuf),
    #[error("config file has no file name: {0}")]
    NoFileName(PathBuf),
    #[error(transparent)]
    Notify(#[from] notify::Error),
}

/// Running watcher. Drop = stop watching.
pub struct CacheRuleWatcher {
    _watcher: RecommendedWatcher,
}

impl CacheRuleWatcher {
    /// Spawn a background thread that reloads `holder` whenever `path`
    /// changes on disk. The notify watcher must be kept alive (drop = stop),
    /// so callers must hold this returned struct for the desired lifetime.
    pub fn spawn(path: PathBuf, holder: Arc<RuleSetHolder>, debounce_ms: u64) -> Result<Self, CacheWatcherError> {
        let parent = path
            .parent()
            .ok_or_else(|| CacheWatcherError::NoParent(path.clone()))?
            .to_path_buf();
        let file_name = path
            .file_name()
            .ok_or_else(|| CacheWatcherError::NoFileName(path.clone()))?
            .to_os_string();

        let (tx, rx) = std::sync::mpsc::channel::<notify::Result<Event>>();
        let mut watcher = RecommendedWatcher::new(tx, Config::default())?;
        watcher.watch(&parent, RecursiveMode::NonRecursive)?;
        info!(file = %path.display(), "cache rules hot-reload watching");

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
                    Ok(Err(e)) => warn!(error = %e, "cache rule watch error"),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        if pending && last_event.elapsed() >= debounce {
                            pending = false;
                            reload(&reload_path, &holder);
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        info!("cache rule watcher channel closed; stopping");
                        break;
                    }
                }
            }
        });

        Ok(Self { _watcher: watcher })
    }
}

/// Public so integration tests can drive the same code path without racing
/// the debounce.
pub fn reload(path: &Path, holder: &RuleSetHolder) {
    match try_load(path) {
        Ok(set) => {
            let count = set.rules.len();
            holder.swap(set);
            info!(rule_count = count, "cache_reload_ok");
        }
        Err(err) => {
            warn!(error = %err, path = %path.display(), "cache_reload_fail; keeping previous ruleset");
        }
    }
}

/// Boot helper: if the file is missing, return an empty set with a warning;
/// any other error (parse / compile) is fatal so operators see typos loudly.
pub fn load_or_empty(path: &Path) -> anyhow::Result<CompiledRuleSet> {
    match std::fs::read_to_string(path) {
        Ok(raw) => parse_and_compile(&raw),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            warn!(path = %path.display(), "cache rules file missing; using empty ruleset");
            Ok(CompiledRuleSet::empty())
        }
        Err(e) => Err(e.into()),
    }
}

fn try_load(path: &Path) -> anyhow::Result<CompiledRuleSet> {
    let raw = std::fs::read_to_string(path)?;
    parse_and_compile(&raw)
}

fn parse_and_compile(raw: &str) -> anyhow::Result<CompiledRuleSet> {
    let doc: CacheConfigDoc = serde_yaml::from_str(raw)?;
    Ok(CompiledRuleSet::try_from_doc(doc)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_yaml() {
        let raw = r"
version: 1
rules:
  - id: r1
    match:
      path: { prefix: /static/ }
    ttl_seconds: 600
    tags: [static]
";
        let set = parse_and_compile(raw).expect("parse ok");
        assert_eq!(set.rules.len(), 1);
    }

    #[test]
    fn parse_unknown_version_is_compile_error() {
        let raw = "version: 9\nrules: []\n";
        assert!(parse_and_compile(raw).is_err());
    }

    #[test]
    fn parse_invalid_yaml_is_error() {
        let raw = "version: [not-an-int]\n";
        assert!(parse_and_compile(raw).is_err());
    }

    #[test]
    fn load_or_empty_returns_empty_when_missing() {
        let path = std::env::temp_dir().join("definitely_does_not_exist_cache_rules.yaml");
        let _ = std::fs::remove_file(&path);
        let set = load_or_empty(&path).expect("missing → ok");
        assert_eq!(set.rules.len(), 0);
    }
}
