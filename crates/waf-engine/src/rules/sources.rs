//! Rule source definitions — local files, remote URLs, built-in sets.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::formats::RuleFormat;

/// A configured source from which rules are loaded.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleSource {
    /// A single local file
    LocalFile {
        name: String,
        path: PathBuf,
        format: RuleFormat,
    },
    /// A local directory (all matching files are loaded)
    LocalDir {
        name: String,
        path: PathBuf,
        /// Glob pattern to match files, e.g. "*.yaml"
        glob: String,
    },
    /// A remote URL (fetched via HTTP and cached locally)
    RemoteUrl {
        name: String,
        url: String,
        format: RuleFormat,
        /// How often to refresh the remote source
        update_interval_secs: u64,
    },
    /// A built-in source compiled into the binary
    Builtin { name: String },
}

impl RuleSource {
    pub fn name(&self) -> &str {
        match self {
            Self::LocalFile { name, .. }
            | Self::LocalDir { name, .. }
            | Self::RemoteUrl { name, .. }
            | Self::Builtin { name } => name,
        }
    }

    pub const fn source_type(&self) -> &'static str {
        match self {
            Self::LocalFile { .. } => "local_file",
            Self::LocalDir { .. } => "local_dir",
            Self::RemoteUrl { .. } => "remote_url",
            Self::Builtin { .. } => "builtin",
        }
    }

    pub const fn update_interval(&self) -> Option<Duration> {
        match self {
            Self::RemoteUrl {
                update_interval_secs, ..
            } => Some(Duration::from_secs(*update_interval_secs)),
            _ => None,
        }
    }
}

/// Load report after `RuleManager::load_all()`.
#[derive(Debug, Default, Clone)]
pub struct RuleLoadReport {
    pub sources_loaded: usize,
    pub rules_loaded: usize,
    pub rules_skipped: usize,
    pub errors: Vec<String>,
}

impl RuleLoadReport {
    pub fn merge(&mut self, other: Self) {
        self.sources_loaded += other.sources_loaded;
        self.rules_loaded += other.rules_loaded;
        self.rules_skipped += other.rules_skipped;
        self.errors.extend(other.errors);
    }
}

impl std::fmt::Display for RuleLoadReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Loaded {} rules from {} sources ({} skipped, {} errors)",
            self.rules_loaded,
            self.sources_loaded,
            self.rules_skipped,
            self.errors.len()
        )
    }
}

/// Reload report after `RuleManager::reload()`.
#[derive(Debug, Clone)]
pub struct RuleReloadReport {
    pub added: usize,
    pub removed: usize,
    pub unchanged: usize,
    pub errors: Vec<String>,
}

impl std::fmt::Display for RuleReloadReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Reload complete: +{} -{} ={} ({} errors)",
            self.added,
            self.removed,
            self.unchanged,
            self.errors.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml_format() -> RuleFormat {
        RuleFormat::Yaml
    }

    #[test]
    fn rule_source_name_returns_inner_name_for_each_variant() {
        let local_file = RuleSource::LocalFile {
            name: "lf".to_string(),
            path: PathBuf::from("/tmp/rules.yaml"),
            format: yaml_format(),
        };
        let local_dir = RuleSource::LocalDir {
            name: "ld".to_string(),
            path: PathBuf::from("/tmp/rules"),
            glob: "*.yaml".to_string(),
        };
        let remote = RuleSource::RemoteUrl {
            name: "ru".to_string(),
            url: "https://example.com/rules.yaml".to_string(),
            format: yaml_format(),
            update_interval_secs: 60,
        };
        let builtin = RuleSource::Builtin { name: "bi".to_string() };

        assert_eq!(local_file.name(), "lf");
        assert_eq!(local_dir.name(), "ld");
        assert_eq!(remote.name(), "ru");
        assert_eq!(builtin.name(), "bi");

        assert_eq!(local_file.source_type(), "local_file");
        assert_eq!(local_dir.source_type(), "local_dir");
        assert_eq!(remote.source_type(), "remote_url");
        assert_eq!(builtin.source_type(), "builtin");
    }

    #[test]
    fn rule_source_update_interval_only_set_for_remote_url() {
        let remote = RuleSource::RemoteUrl {
            name: "ru".to_string(),
            url: "https://example.com".to_string(),
            format: yaml_format(),
            update_interval_secs: 30,
        };
        assert_eq!(remote.update_interval(), Some(Duration::from_secs(30)));

        let builtin = RuleSource::Builtin { name: "bi".to_string() };
        assert_eq!(builtin.update_interval(), None);

        let local_file = RuleSource::LocalFile {
            name: "lf".to_string(),
            path: PathBuf::from("/tmp/x"),
            format: yaml_format(),
        };
        assert_eq!(local_file.update_interval(), None);

        let local_dir = RuleSource::LocalDir {
            name: "ld".to_string(),
            path: PathBuf::from("/tmp"),
            glob: "*".to_string(),
        };
        assert_eq!(local_dir.update_interval(), None);
    }

    #[test]
    fn rule_load_report_merge_accumulates_fields() {
        let mut a = RuleLoadReport {
            sources_loaded: 1,
            rules_loaded: 10,
            rules_skipped: 2,
            errors: vec!["e1".to_string()],
        };
        let b = RuleLoadReport {
            sources_loaded: 2,
            rules_loaded: 5,
            rules_skipped: 0,
            errors: vec!["e2".to_string(), "e3".to_string()],
        };
        a.merge(b);
        assert_eq!(a.sources_loaded, 3);
        assert_eq!(a.rules_loaded, 15);
        assert_eq!(a.rules_skipped, 2);
        assert_eq!(a.errors, vec!["e1", "e2", "e3"]);
    }

    #[test]
    fn rule_load_report_display_format() {
        let report = RuleLoadReport {
            sources_loaded: 4,
            rules_loaded: 100,
            rules_skipped: 3,
            errors: vec!["x".to_string()],
        };
        assert_eq!(
            format!("{report}"),
            "Loaded 100 rules from 4 sources (3 skipped, 1 errors)"
        );
    }

    #[test]
    fn rule_reload_report_display_format() {
        let report = RuleReloadReport {
            added: 5,
            removed: 2,
            unchanged: 7,
            errors: vec![],
        };
        assert_eq!(format!("{report}"), "Reload complete: +5 -2 =7 (0 errors)");
    }
}
