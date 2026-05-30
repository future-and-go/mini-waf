//! FR-012 phase-01 — YAML schema, parser, and hot-reload watcher for
//! `configs/tx-velocity.yaml`.
//!
//! Mirrors `checks::rate_limit::config` + `checks::rate_limit::reload`:
//! `deny_unknown_fields` everywhere, `notify` parent-dir watcher, fail-soft
//! on parse error (previous snapshot retained). Drop the returned
//! [`TxVelocityReloader`] to stop watching.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use arc_swap::ArcSwap;
use notify::{Config as NotifyConfig, Event, RecommendedWatcher, RecursiveMode, Watcher};
use serde::Deserialize;
use tracing::{info, warn};

use super::EndpointRole;
use super::role_tagger::RoleTagger;

const SCHEMA_VERSION: u32 = 1;
const DEFAULT_DEBOUNCE_MS: u64 = 200;

// ─── Defaults ────────────────────────────────────────────────────────────────

const fn default_schema_version() -> u32 {
    SCHEMA_VERSION
}
const fn default_signal_cooldown_ms() -> u64 {
    5_000
}
const fn default_session_ttl_secs() -> u64 {
    600
}
const fn default_janitor_period_secs() -> u64 {
    60
}
const fn default_dedupe_window_ms() -> u64 {
    5_000
}
fn default_session_cookie() -> String {
    "SESSIONID".to_string()
}

// ─── DTO (operator-facing YAML) ──────────────────────────────────────────────

/// Top-level YAML wrapper: `tx_velocity:` is the single root key.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TxVelocityDocument {
    #[serde(default)]
    pub tx_velocity: TxVelocityFileConfig,
}

/// Operator YAML schema. Empty file ⇒ inert (`enabled = false`,
/// no roles).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TxVelocityFileConfig {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_session_cookie")]
    pub session_cookie: String,
    #[serde(default = "default_signal_cooldown_ms")]
    pub signal_cooldown_ms: u64,
    #[serde(default = "default_session_ttl_secs")]
    pub session_ttl_secs: u64,
    #[serde(default = "default_janitor_period_secs")]
    pub janitor_period_secs: u64,
    /// Collapse same-(key, role, Pending) events within this window into
    /// one slot. Defuses mobile retry storms.
    #[serde(default = "default_dedupe_window_ms")]
    pub dedupe_window_ms: u64,
    /// Path-pattern → role rules. Evaluated in order; first match wins.
    #[serde(default)]
    pub endpoint_roles: Vec<RoleRule>,
    /// Classifier knobs. Phase 1 carries placeholder structs only.
    #[serde(default)]
    pub classifiers: ClassifierConfigs,
}

impl Default for TxVelocityFileConfig {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            enabled: false,
            session_cookie: default_session_cookie(),
            signal_cooldown_ms: default_signal_cooldown_ms(),
            session_ttl_secs: default_session_ttl_secs(),
            janitor_period_secs: default_janitor_period_secs(),
            dedupe_window_ms: default_dedupe_window_ms(),
            endpoint_roles: Vec::new(),
            classifiers: ClassifierConfigs::default(),
        }
    }
}

/// One role rule: `path` is a regex matched against `RequestCtx::path`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleRule {
    pub role: EndpointRole,
    pub path: String,
}

/// Classifier parameter blocks. Phase 1 keeps them present so YAML
/// authored against the final schema still parses; values are unused
/// until Phase 2 wires real classifiers.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassifierConfigs {
    #[serde(default)]
    pub sequence: Option<SequenceCfg>,
    #[serde(default)]
    pub withdrawal_velocity: Option<VelocityCfg>,
    #[serde(default)]
    pub limit_change_velocity: Option<VelocityCfg>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SequenceCfg {
    /// Login → OTP → Deposit completed faster than this ⇒ suspicious.
    pub min_human_ms: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VelocityCfg {
    pub max_count: u32,
    pub window_ms: u64,
}

// ─── Runtime config (consumed by recorder + classifiers) ─────────────────────

/// Validated runtime snapshot. Held inside `ArcSwap` for hot-reload.
#[derive(Debug)]
pub struct TxVelocityConfig {
    pub enabled: bool,
    pub session_cookie: String,
    pub signal_cooldown_ms: u64,
    pub session_ttl_secs: u64,
    pub janitor_period_secs: u64,
    pub dedupe_window_ms: u64,
    pub role_tagger: RoleTagger,
    pub classifiers: ClassifierConfigs,
}

impl Default for TxVelocityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            session_cookie: default_session_cookie(),
            signal_cooldown_ms: default_signal_cooldown_ms(),
            session_ttl_secs: default_session_ttl_secs(),
            janitor_period_secs: default_janitor_period_secs(),
            dedupe_window_ms: default_dedupe_window_ms(),
            role_tagger: RoleTagger::empty(),
            classifiers: ClassifierConfigs::default(),
        }
    }
}

impl TxVelocityFileConfig {
    /// Parse from raw YAML text → validated runtime snapshot.
    pub fn from_yaml_str(s: &str) -> Result<Arc<TxVelocityConfig>> {
        let doc: TxVelocityDocument = serde_yaml::from_str(s).context("tx_velocity: parse YAML")?;
        let cfg = doc.tx_velocity;
        cfg.validate()?;
        Ok(Arc::new(cfg.into_runtime()?))
    }

    /// Parse from file path.
    pub fn from_path(path: &Path) -> Result<Arc<TxVelocityConfig>> {
        let raw = std::fs::read_to_string(path).with_context(|| format!("tx_velocity: read {}", path.display()))?;
        Self::from_yaml_str(&raw)
    }

    fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            bail!(
                "tx_velocity: unsupported schema_version {} (this build expects {})",
                self.schema_version,
                SCHEMA_VERSION
            );
        }
        if self.session_cookie.is_empty() {
            bail!("tx_velocity: session_cookie must not be empty");
        }
        if self.session_ttl_secs == 0 {
            bail!("tx_velocity: session_ttl_secs must be > 0");
        }
        if self.janitor_period_secs == 0 {
            bail!("tx_velocity: janitor_period_secs must be > 0");
        }
        for (idx, rule) in self.endpoint_roles.iter().enumerate() {
            if rule.path.is_empty() {
                bail!("tx_velocity.endpoint_roles[{idx}]: path must not be empty");
            }
            // Reject obviously ReDoS-prone patterns: nested unbounded
            // quantifiers like `(.*)*` / `(.+)+`. The `regex` crate is
            // linear-time so this is belt-and-braces, not strictly required.
            if rule.path.contains("*)*") || rule.path.contains("+)+") {
                bail!("tx_velocity.endpoint_roles[{idx}]: nested unbounded quantifiers are rejected");
            }
        }
        Ok(())
    }

    fn into_runtime(self) -> Result<TxVelocityConfig> {
        let role_tagger = if self.enabled {
            RoleTagger::compile(&self.endpoint_roles).context("tx_velocity: compile role rules")?
        } else {
            RoleTagger::empty()
        };
        Ok(TxVelocityConfig {
            enabled: self.enabled,
            session_cookie: self.session_cookie,
            signal_cooldown_ms: self.signal_cooldown_ms,
            session_ttl_secs: self.session_ttl_secs,
            janitor_period_secs: self.janitor_period_secs,
            dedupe_window_ms: self.dedupe_window_ms,
            role_tagger,
            classifiers: self.classifiers,
        })
    }
}

// ─── Hot-reload watcher ──────────────────────────────────────────────────────

/// Owns the background watcher thread + the `notify` watcher itself.
/// Drop = stop watching.
pub struct TxVelocityReloader {
    _watcher: RecommendedWatcher,
}

impl TxVelocityReloader {
    /// Spawn a watcher that swaps `swap` whenever `path` changes.
    pub fn start(path: PathBuf, swap: Arc<ArcSwap<TxVelocityConfig>>, debounce_ms: Option<u64>) -> Result<Self> {
        let watcher = spawn_watch(path, debounce_ms.unwrap_or(DEFAULT_DEBOUNCE_MS), move |p| {
            reload(p, &swap);
        })?;
        Ok(Self { _watcher: watcher })
    }
}

fn reload(path: &Path, swap: &Arc<ArcSwap<TxVelocityConfig>>) {
    match TxVelocityFileConfig::from_path(path) {
        Ok(cfg) => {
            swap.store(cfg);
            info!(file = %path.display(), "tx_velocity: hot-reload OK");
        }
        Err(e) => {
            warn!(
                file = %path.display(),
                error = %e,
                "tx_velocity: hot-reload failed; keeping previous snapshot"
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
        .ok_or_else(|| anyhow!("tx_velocity watch path has no parent: {}", path.display()))?
        .to_path_buf();
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("tx_velocity watch path has no file name: {}", path.display()))?
        .to_os_string();

    let (tx, rx) = std::sync::mpsc::channel::<notify::Result<Event>>();
    let mut watcher = RecommendedWatcher::new(tx, NotifyConfig::default())?;
    watcher.watch(&parent, RecursiveMode::NonRecursive)?;
    info!(file = %path.display(), "tx_velocity: hot-reload watching");

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
                Ok(Err(e)) => warn!(error = %e, "tx_velocity: notify channel error"),
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

    #[test]
    fn empty_yaml_parses_inert() {
        let cfg = TxVelocityFileConfig::from_yaml_str("").expect("empty parses");
        assert!(!cfg.enabled);
        assert_eq!(cfg.session_cookie, "SESSIONID");
        assert_eq!(cfg.signal_cooldown_ms, 5_000);
    }

    #[test]
    fn full_yaml_round_trip() {
        let yaml = r#"
tx_velocity:
  schema_version: 1
  enabled: true
  session_cookie: TXSID
  signal_cooldown_ms: 3000
  session_ttl_secs: 900
  janitor_period_secs: 30
  endpoint_roles:
    - role: login
      path: "^/api/login$"
    - role: otp
      path: "^/api/otp/verify$"
    - role: deposit
      path: "^/api/deposit$"
  classifiers:
    sequence:
      min_human_ms: 1500
    withdrawal_velocity:
      max_count: 3
      window_ms: 60000
"#;
        let cfg = TxVelocityFileConfig::from_yaml_str(yaml).expect("parses");
        assert!(cfg.enabled);
        assert_eq!(cfg.session_cookie, "TXSID");
        assert_eq!(cfg.signal_cooldown_ms, 3_000);
        assert_eq!(cfg.session_ttl_secs, 900);
        // Role tagger maps a known login path.
        assert_eq!(cfg.role_tagger.classify("/api/login"), EndpointRole::Login);
        assert_eq!(cfg.role_tagger.classify("/api/otp/verify"), EndpointRole::Otp);
        assert_eq!(cfg.role_tagger.classify("/unrelated"), EndpointRole::None);
    }

    #[test]
    fn unknown_field_rejected() {
        let yaml = r"
tx_velocity:
  enabled: true
  bogus_field: 42
";
        assert!(TxVelocityFileConfig::from_yaml_str(yaml).is_err());
    }

    #[test]
    fn schema_mismatch_rejected() {
        let yaml = r"
tx_velocity:
  schema_version: 999
";
        let err = TxVelocityFileConfig::from_yaml_str(yaml).unwrap_err().to_string();
        assert!(err.contains("schema_version"), "got: {err}");
    }

    #[test]
    fn empty_path_rejected() {
        let yaml = r#"
tx_velocity:
  enabled: true
  endpoint_roles:
    - role: login
      path: ""
"#;
        assert!(TxVelocityFileConfig::from_yaml_str(yaml).is_err());
    }

    #[test]
    fn nested_quantifier_rejected() {
        let yaml = r#"
tx_velocity:
  enabled: true
  endpoint_roles:
    - role: login
      path: "(.*)*evil"
"#;
        assert!(TxVelocityFileConfig::from_yaml_str(yaml).is_err());
    }

    #[test]
    fn disabled_skips_regex_compile() {
        let yaml = r#"
tx_velocity:
  enabled: false
  endpoint_roles:
    - role: login
      path: "[invalid("
"#;
        // Disabled ⇒ tagger is empty, bad regex is not compiled.
        let cfg = TxVelocityFileConfig::from_yaml_str(yaml).expect("parses when disabled");
        assert!(!cfg.enabled);
    }
}
