//! FR-003 file-based custom rule loader.
//!
//! Scans `<rules_dir>/custom/*.yaml`, parses each file via
//! `formats::custom_rule_yaml::parse`, and returns a flat `Vec<CustomRule>`.
//! Per-file parse errors are logged and skipped — never abort the whole load.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::{info, warn};

use super::engine::{CustomRule, CustomRulesEngine};
use super::formats::custom_rule_yaml;

const CUSTOM_SUBDIR: &str = "custom";
const YAML_EXT: &str = "yaml";

/// Load every `<rules_root>/custom/*.yaml` file as `CustomRule`s.
///
/// Returns an empty vec if `<rules_root>/custom` does not exist (this is
/// normal for fresh installs). Subdirectories are ignored, so sample
/// folders like `custom/fr003-samples/` do not pollute the live rule set.
pub fn load_dir(rules_root: &Path) -> Result<Vec<CustomRule>> {
    let custom_dir = rules_root.join(CUSTOM_SUBDIR);
    if !custom_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    for entry in std::fs::read_dir(&custom_dir)? {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warn!(dir = %custom_dir.display(), err = %e, "custom rule dir entry read failed");
                continue;
            }
        };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some(YAML_EXT) {
            continue;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                warn!(file = %path.display(), err = %e, "custom rule file read failed");
                continue;
            }
        };
        match custom_rule_yaml::parse(&content) {
            Ok(rules) => out.extend(rules),
            Err(e) => warn!(file = %path.display(), err = %e, "custom rule parse failed"),
        }
    }
    Ok(out)
}

/// Background watcher that hot-reloads `<rules_dir>/custom/*.yaml` rules
/// into a `CustomRulesEngine` whenever files in that directory change.
///
/// Drop the value to stop watching: both the notify watcher and the
/// debounce/reload thread tear down cleanly when their channels close.
pub struct CustomRuleFileWatcher {
    /// Held alive so the OS-level watch isn't dropped.
    _watcher: RecommendedWatcher,
}

impl CustomRuleFileWatcher {
    /// Spawn a watcher on `<rules_root>/custom/`.
    ///
    /// On any create/modify/remove event, debounces 500ms then:
    ///   1. `engine.clear_file_rules()` — drops stale file entries.
    ///   2. `load_dir(rules_root)` — re-parses all yaml files.
    ///   3. `engine.add_file_rule(rule)` per result.
    ///
    /// If the directory is missing, it is created so the OS-level watch
    /// can attach. Watcher creation errors propagate to the caller.
    pub fn spawn(rules_root: PathBuf, engine: Arc<CustomRulesEngine>) -> Result<Self> {
        let custom_dir = rules_root.join(CUSTOM_SUBDIR);
        if !custom_dir.exists() {
            std::fs::create_dir_all(&custom_dir)?;
        }

        let (tx, rx) = std::sync::mpsc::channel::<notify::Result<Event>>();
        let mut watcher = RecommendedWatcher::new(tx, Config::default())?;
        watcher.watch(&custom_dir, RecursiveMode::NonRecursive)?;
        info!(path = %custom_dir.display(), "Custom-rule file watcher started");

        std::thread::spawn(move || run_event_loop(rx, rules_root, engine));

        Ok(Self { _watcher: watcher })
    }
}

const DEBOUNCE: Duration = Duration::from_millis(500);

// Thread entry point — owns its arguments for the lifetime of the watcher
// thread. Passing by reference would dangle once `spawn` returns.
#[allow(clippy::needless_pass_by_value)]
fn run_event_loop(
    rx: std::sync::mpsc::Receiver<notify::Result<Event>>,
    rules_root: PathBuf,
    engine: Arc<CustomRulesEngine>,
) {
    let mut last_event = std::time::Instant::now();
    let mut pending = false;

    loop {
        match rx.recv_timeout(DEBOUNCE) {
            Ok(Ok(event)) => {
                // FSEvents on macOS sometimes reports `EventKind::Any` instead
                // of a precise variant. Accept anything that isn't an Access
                // event so we cover Create / Modify / Remove on every backend.
                if !matches!(event.kind, EventKind::Access(_)) {
                    last_event = std::time::Instant::now();
                    pending = true;
                }
            }
            Ok(Err(e)) => warn!(error = %e, "custom-rule watcher event error"),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if pending && last_event.elapsed() >= DEBOUNCE {
                    pending = false;
                    reload_now(&rules_root, &engine);
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                info!("Custom-rule file watcher channel closed; stopping");
                break;
            }
        }
    }
}

fn reload_now(rules_root: &Path, engine: &CustomRulesEngine) {
    engine.clear_file_rules();
    match load_dir(rules_root) {
        Ok(rules) => {
            let n = rules.len();
            for r in rules {
                engine.add_file_rule(r);
            }
            info!("Reloaded {n} file-based custom rules");
        }
        Err(e) => warn!(error = %e, "File rule reload failed"),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn returns_empty_when_custom_dir_missing() {
        let tmp = tempdir().unwrap();
        let rules = load_dir(tmp.path()).unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn loads_single_yaml_file() {
        let tmp = tempdir().unwrap();
        let custom = tmp.path().join("custom");
        fs::create_dir_all(&custom).unwrap();
        fs::write(
            custom.join("rule.yaml"),
            "kind: custom_rule_v1\nid: r1\nname: test\nconditions:\n  - field: path\n    operator: eq\n    value: /x\n",
        )
        .unwrap();

        let rules = load_dir(tmp.path()).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "r1");
    }

    #[test]
    fn skips_subdirectories() {
        let tmp = tempdir().unwrap();
        let nested = tmp.path().join("custom").join("samples");
        fs::create_dir_all(&nested).unwrap();
        // Sample inside subdir must NOT be picked up.
        fs::write(
            nested.join("ignored.yaml"),
            "kind: custom_rule_v1\nid: ignored\nname: x\n",
        )
        .unwrap();

        let rules = load_dir(tmp.path()).unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn bad_file_does_not_abort_others() {
        let tmp = tempdir().unwrap();
        let custom = tmp.path().join("custom");
        fs::create_dir_all(&custom).unwrap();
        // Malformed kind → parse error, logged + skipped.
        fs::write(custom.join("bad.yaml"), "kind: custom_rule_v999\nid: x\nname: x\n").unwrap();
        // Good file alongside.
        fs::write(custom.join("good.yaml"), "kind: custom_rule_v1\nid: ok\nname: ok\n").unwrap();

        let rules = load_dir(tmp.path()).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "ok");
    }

    #[test]
    fn ignores_non_yaml_extensions() {
        let tmp = tempdir().unwrap();
        let custom = tmp.path().join("custom");
        fs::create_dir_all(&custom).unwrap();
        fs::write(custom.join("README.md"), "not a rule").unwrap();
        fs::write(custom.join("rule.json"), "{}").unwrap();

        let rules = load_dir(tmp.path()).unwrap();
        assert!(rules.is_empty());
    }
}
