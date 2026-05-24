//! Hot-reload — watches the rules directory for file changes and triggers reloads.
//!
//! Uses the `notify` crate for file-system events and optionally handles SIGHUP.
//! Debounces rapid successive changes by waiting `debounce_ms` after the last event.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use anyhow::Result;
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::{info, warn};

use super::manager::RuleManager;

/// File extensions that should trigger a rule reload.
const RELEVANT_EXTENSIONS: &[&str] = &["yaml", "yml", "data"];

/// A running file-system watcher that triggers rule reloads.
///
/// Drop this value to stop watching.
pub struct HotReloader {
    /// The underlying notify watcher (kept alive for the watcher's lifetime)
    _watcher: RecommendedWatcher,
}

impl HotReloader {
    /// Start watching `rules_dir` and trigger reloads on any change.
    ///
    /// `manager` is shared (Arc<Mutex>) so the watcher thread can call `reload()`.
    /// `debounce_ms` controls how long to wait after the last event before reloading.
    #[allow(clippy::needless_pass_by_value)]
    pub fn start(manager: Arc<Mutex<RuleManager>>, rules_dir: PathBuf, debounce_ms: u64) -> Result<Self> {
        let (tx, rx) = std::sync::mpsc::channel::<notify::Result<Event>>();

        let mut watcher = RecommendedWatcher::new(tx, Config::default())?;

        // Create the directory if it doesn't exist yet
        if !rules_dir.exists()
            && let Err(e) = std::fs::create_dir_all(&rules_dir)
        {
            warn!(path = %rules_dir.display(), "Failed to create rules directory: {e}");
        }

        watcher.watch(&rules_dir, RecursiveMode::Recursive)?;
        info!(path = %rules_dir.display(), "Hot-reload watching rules directory");

        // Spawn a background thread to receive events and trigger reloads
        std::thread::spawn(move || {
            let debounce = Duration::from_millis(debounce_ms);
            let mut last_event = std::time::Instant::now();
            let mut pending = false;

            loop {
                match rx.recv_timeout(debounce) {
                    Ok(Ok(event)) => {
                        let relevant_kind = matches!(
                            event.kind,
                            notify::EventKind::Create(_) | notify::EventKind::Modify(_) | notify::EventKind::Remove(_)
                        );
                        if relevant_kind && has_relevant_extension(&event) {
                            last_event = std::time::Instant::now();
                            pending = true;
                        }
                    }
                    Ok(Err(e)) => warn!("hot-reload watch error: {e}"),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        // Check if enough time has passed since the last event
                        if pending && last_event.elapsed() >= debounce {
                            pending = false;
                            trigger_reload(&manager);
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        info!("Hot-reload watcher channel closed, stopping");
                        break;
                    }
                }
            }
        });

        Ok(Self { _watcher: watcher })
    }
}

/// Returns `true` if any path in `event` has a rule-relevant extension.
fn has_relevant_extension(event: &Event) -> bool {
    event.paths.iter().any(|p| is_relevant_rule_file(p))
}

fn is_relevant_rule_file(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| RELEVANT_EXTENSIONS.iter().any(|r| r.eq_ignore_ascii_case(ext)))
}

fn trigger_reload(manager: &Arc<Mutex<RuleManager>>) {
    let mut mgr = manager.lock();
    match mgr.reload() {
        Ok(report) => info!("Hot-reload: {report}"),
        Err(e) => warn!("Hot-reload failed: {e}"),
    }
}

/// Register a SIGHUP handler that triggers a rule reload (Unix only).
///
/// Returns immediately. The handler runs in a background tokio task.
#[cfg(unix)]
pub fn register_sighup_handler(manager: Arc<Mutex<RuleManager>>) {
    tokio::spawn(async move {
        use tokio::signal::unix::{SignalKind, signal};
        let mut stream = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to register SIGHUP handler: {e}");
                return;
            }
        };
        loop {
            stream.recv().await;
            info!("SIGHUP received — reloading rules");
            let mgr = Arc::clone(&manager);
            if let Err(e) = tokio::task::spawn_blocking(move || {
                trigger_reload(&mgr);
            })
            .await
            {
                warn!("SIGHUP reload task panicked: {e}");
            }
        }
    });
}

/// No-op on non-Unix platforms.
#[cfg(not(unix))]
pub fn register_sighup_handler(_manager: Arc<Mutex<RuleManager>>) {}

#[cfg(test)]
#[allow(clippy::redundant_clone)]
mod tests {
    use super::*;
    use waf_common::RulesConfig;

    fn empty_manager() -> Arc<Mutex<RuleManager>> {
        let cfg = RulesConfig {
            enable_builtin_owasp: false,
            enable_builtin_bot: false,
            enable_builtin_scanner: false,
            ..RulesConfig::default()
        };
        Arc::new(Mutex::new(RuleManager::new(&cfg)))
    }

    #[test]
    fn start_creates_missing_rules_directory() {
        let tmp = tempfile::tempdir().expect("tmp");
        let rules_dir = tmp.path().join("does-not-exist");
        assert!(!rules_dir.exists());

        let mgr = empty_manager();
        // Hold the watcher to keep the OS handle alive briefly.
        let _hr = HotReloader::start(mgr, rules_dir.clone(), 50).expect("start");
        assert!(rules_dir.exists());
    }

    #[test]
    fn trigger_reload_handles_empty_manager() {
        let mgr = empty_manager();
        // Just exercises the success path: no sources → empty report.
        trigger_reload(&mgr);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn register_sighup_handler_does_not_panic() {
        let mgr = empty_manager();
        register_sighup_handler(mgr);
        // Yield so the spawned task can install the signal handler.
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    #[test]
    fn watcher_handles_file_create_modify_remove_events() {
        let tmp = tempfile::tempdir().expect("tmp");
        let rules_dir = tmp.path().to_path_buf();
        let mgr = empty_manager();
        let _hr = HotReloader::start(Arc::clone(&mgr), rules_dir.clone(), 50).expect("start");

        // Wait for watcher thread to start.
        std::thread::sleep(Duration::from_millis(60));

        // Create a file → CreateEvent → triggers reload after debounce.
        let f = rules_dir.join("rule.yaml");
        std::fs::write(&f, "- id: A\n  name: a\n").expect("write");
        std::thread::sleep(Duration::from_millis(150));

        // Modify event.
        std::fs::write(&f, "- id: A\n  name: aa\n").expect("modify");
        std::thread::sleep(Duration::from_millis(150));

        // Remove event.
        std::fs::remove_file(&f).expect("remove");
        std::thread::sleep(Duration::from_millis(150));

        // Did not panic — manager still callable.
        let stats = mgr.lock().stats();
        assert_eq!(stats.total, 0);
    }

    #[test]
    fn watcher_drop_stops_thread() {
        let tmp = tempfile::tempdir().expect("tmp");
        let rules_dir = tmp.path().to_path_buf();
        let mgr = empty_manager();
        {
            let _hr = HotReloader::start(Arc::clone(&mgr), rules_dir.clone(), 30).expect("start");
            std::thread::sleep(Duration::from_millis(50));
        } // dropped here — channel closes, thread should exit cleanly
        std::thread::sleep(Duration::from_millis(50));
    }

    #[test]
    fn is_relevant_rule_file_accepts_yaml_yml_data() {
        assert!(is_relevant_rule_file(Path::new("rules/test.yaml")));
        assert!(is_relevant_rule_file(Path::new("rules/test.yml")));
        assert!(is_relevant_rule_file(Path::new("rules/data/restricted-files.data")));
        assert!(is_relevant_rule_file(Path::new("test.YAML")));
    }

    #[test]
    fn is_relevant_rule_file_rejects_other_extensions() {
        assert!(!is_relevant_rule_file(Path::new("README.md")));
        assert!(!is_relevant_rule_file(Path::new("rules/config.json")));
        assert!(!is_relevant_rule_file(Path::new("rules/notes.txt")));
        assert!(!is_relevant_rule_file(Path::new("no_extension")));
    }

    #[test]
    fn watcher_reacts_to_data_file_changes() {
        let tmp = tempfile::tempdir().expect("tmp");
        let rules_dir = tmp.path().to_path_buf();
        let data_dir = rules_dir.join("data");
        std::fs::create_dir_all(&data_dir).expect("create data dir");

        let mgr = empty_manager();
        let _hr = HotReloader::start(Arc::clone(&mgr), rules_dir.clone(), 50).expect("start");

        std::thread::sleep(Duration::from_millis(60));

        let f = data_dir.join("test.data");
        std::fs::write(&f, "forbidden\n").expect("write .data");
        std::thread::sleep(Duration::from_millis(150));

        std::fs::write(&f, "forbidden\nnewbad\n").expect("modify .data");
        std::thread::sleep(Duration::from_millis(150));

        // Did not panic — manager still callable after .data changes.
        let stats = mgr.lock().stats();
        assert_eq!(stats.total, 0);
    }
}
