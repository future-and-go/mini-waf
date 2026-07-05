//! Hot-reload watcher for `configs/geo-rules.yaml`.
//!
//! Mirrors `ddos::reload`: parent-dir `notify` watcher on a sync
//! `std::thread`, debounced, fail-soft on parse error (previous rule set
//! retained). The admin API writes the same file, so geo rule CRUD
//! hot-reloads with no extra API→engine call. Drop the returned
//! [`GeoReloader`] to stop watching.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use notify::{Config as NotifyConfig, Event, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::{info, warn};

use super::geo::GeoCheck;
use super::geo_config::apply_geo_rules;

/// 200 ms covers typical editor save bursts (truncate + write + chmod).
pub const DEFAULT_DEBOUNCE_MS: u64 = 200;

/// Owns the background watcher thread + the `notify` watcher itself.
/// Drop = stop watching.
pub struct GeoReloader {
    _watcher: RecommendedWatcher,
}

impl GeoReloader {
    /// Spawn a watcher that reloads `geo_check` whenever `path` changes.
    #[must_use = "dropping the reloader stops file watching"]
    pub fn start(path: PathBuf, geo_check: Arc<GeoCheck>, debounce_ms: u64) -> Result<Self> {
        let watcher = spawn_watch(path, debounce_ms, move |p| reload(p, &geo_check))?;
        Ok(Self { _watcher: watcher })
    }
}

fn reload(path: &Path, geo_check: &Arc<GeoCheck>) {
    match apply_geo_rules(geo_check, path) {
        Ok(()) => info!(file = %path.display(), "geo rules: hot-reload OK"),
        Err(e) => warn!(
            file = %path.display(),
            error = %e,
            "geo rules: hot-reload failed; keeping previous rule set"
        ),
    }
}

fn spawn_watch<F>(path: PathBuf, debounce_ms: u64, mut on_change: F) -> Result<RecommendedWatcher>
where
    F: FnMut(&Path) + Send + 'static,
{
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("geo watch path has no parent: {}", path.display()))?
        .to_path_buf();
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("geo watch path has no file name: {}", path.display()))?
        .to_os_string();

    let (tx, rx) = std::sync::mpsc::channel::<notify::Result<Event>>();
    let mut watcher = RecommendedWatcher::new(tx, NotifyConfig::default())?;
    watcher.watch(&parent, RecursiveMode::NonRecursive)?;
    info!(file = %path.display(), "geo rules: hot-reload watching");

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
                Ok(Err(e)) => warn!(error = %e, "geo rules: notify channel error"),
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

    fn write_file(path: &Path, contents: &str) {
        let mut f = std::fs::File::create(path).expect("create");
        f.write_all(contents.as_bytes()).expect("write");
        f.sync_all().expect("sync");
    }

    /// End-to-end: writing a new rules file swaps the live rule set.
    #[test]
    fn hot_reload_swaps_rules() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("geo-rules.yaml");
        write_file(&path, "rules: []\n");

        let check = Arc::new(GeoCheck::new());
        let _reloader = GeoReloader::start(path.clone(), Arc::clone(&check), 50).expect("start");

        std::thread::sleep(Duration::from_millis(50));
        write_file(
            &path,
            r#"rules:
  - { id: 1, iso_code: "KP", action: "block", scope: "global", enabled: true }
"#,
        );

        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if check.loaded_hosts().contains(&"*".to_string()) {
                break;
            }
            assert!(Instant::now() < deadline, "hot-reload did not swap within 3s");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Bad YAML retains the previous rule set — no panic, no crash.
    #[test]
    fn bad_yaml_retains_previous_rules() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("geo-rules.yaml");
        write_file(
            &path,
            r#"rules:
  - { id: 1, iso_code: "KP", action: "block", scope: "global", enabled: true }
"#,
        );

        let check = Arc::new(GeoCheck::new());
        apply_geo_rules(&check, &path).expect("initial load");
        let _reloader = GeoReloader::start(path.clone(), Arc::clone(&check), 50).expect("start");

        std::thread::sleep(Duration::from_millis(50));
        write_file(&path, "rules: {not: a list}\n");

        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(
            check.loaded_hosts(),
            vec!["*".to_string()],
            "previous rule set must be retained on parse error"
        );
    }
}
