//! `RuleManager` — loads, reloads, validates, enables/disables rules.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::RwLock;

use anyhow::{Context, Result, bail};
use tracing::{info, warn};

use waf_common::config::RulesConfig;

use super::builtin::all_builtin_rules;
use super::formats::{ExportFormat, RuleFormat, ValidationError, export_rules, parse_rules, validate_rules};
use super::registry::{Rule, RuleRegistry, RuleStats};
use super::sources::{RuleLoadReport, RuleReloadReport, RuleSource};

/// Central rule management component.
///
/// Owns the `RuleRegistry` and knows how to load/reload rules from files,
/// built-ins, and remote sources.
pub struct RuleManager {
    pub registry: Arc<RwLock<RuleRegistry>>,
    pub sources: Vec<RuleSource>,
    pub rules_dir: PathBuf,
    enable_builtin_owasp: bool,
    enable_builtin_bot: bool,
    enable_builtin_scanner: bool,
}

impl RuleManager {
    /// Create a new `RuleManager` from configuration.
    pub fn new(config: &RulesConfig) -> Self {
        let mut sources: Vec<RuleSource> = Vec::new();

        // Convert configured sources into RuleSource variants
        for entry in &config.sources {
            if let Some(url) = &entry.url {
                let format = match entry.format.as_str() {
                    "modsec" => RuleFormat::ModSec,
                    "json" => RuleFormat::Json,
                    _ => RuleFormat::Yaml,
                };
                sources.push(RuleSource::RemoteUrl {
                    name: entry.name.clone(),
                    url: url.clone(),
                    format,
                    update_interval_secs: entry.update_interval,
                });
            } else if let Some(path) = &entry.path {
                let pb = PathBuf::from(path);
                if pb.is_file() {
                    let format = match entry.format.as_str() {
                        "modsec" => RuleFormat::ModSec,
                        "json" => RuleFormat::Json,
                        _ => RuleFormat::Yaml,
                    };
                    sources.push(RuleSource::LocalFile {
                        name: entry.name.clone(),
                        path: pb,
                        format,
                    });
                } else {
                    sources.push(RuleSource::LocalDir {
                        name: entry.name.clone(),
                        path: pb,
                        glob: "*.yaml".to_string(),
                    });
                }
            }
        }

        // Add builtin sources
        if config.enable_builtin_owasp {
            sources.push(RuleSource::Builtin {
                name: "builtin-owasp".to_string(),
            });
        }
        if config.enable_builtin_bot {
            sources.push(RuleSource::Builtin {
                name: "builtin-bot".to_string(),
            });
        }
        if config.enable_builtin_scanner {
            sources.push(RuleSource::Builtin {
                name: "builtin-scanner".to_string(),
            });
        }

        Self {
            registry: Arc::new(RwLock::new(RuleRegistry::new())),
            sources,
            rules_dir: PathBuf::from(&config.dir),
            enable_builtin_owasp: config.enable_builtin_owasp,
            enable_builtin_bot: config.enable_builtin_bot,
            enable_builtin_scanner: config.enable_builtin_scanner,
        }
    }

    /// Load all rules from all configured sources.
    pub fn load_all(&mut self) -> Result<RuleLoadReport> {
        let mut report = RuleLoadReport::default();

        // Load built-in rules
        let builtin = all_builtin_rules(
            self.enable_builtin_owasp,
            self.enable_builtin_bot,
            self.enable_builtin_scanner,
        );
        let builtin_count = builtin.len();

        {
            let mut reg = self.registry.write();
            reg.clear();
            for rule in builtin {
                reg.insert(rule);
            }
        }
        report.rules_loaded += builtin_count;
        report.sources_loaded += 1;

        // Load from rules directory
        if self.rules_dir.is_dir() {
            match self.load_from_dir(&self.rules_dir.clone()) {
                Ok(sub) => report.merge(sub),
                Err(e) => report.errors.push(format!("rules dir: {e}")),
            }
        }

        // Load from configured sources
        let sources = self.sources.clone();
        for source in &sources {
            match source {
                RuleSource::LocalFile { path, format, name } => match load_file(path, *format) {
                    Ok(rules) => {
                        let count = rules.len();
                        {
                            let mut reg = self.registry.write();
                            for rule in rules {
                                reg.insert(rule);
                            }
                        }
                        info!(source = %name, rules = count, "Loaded rules from file");
                        report.rules_loaded += count;
                        report.sources_loaded += 1;
                    }
                    Err(e) => report.errors.push(format!("{name}: {e}")),
                },
                RuleSource::LocalDir { path, name, .. } => match self.load_from_dir(path) {
                    Ok(sub) => {
                        info!(source = %name, rules = sub.rules_loaded, "Loaded rules from dir");
                        report.merge(sub);
                    }
                    Err(e) => report.errors.push(format!("{name}: {e}")),
                },
                RuleSource::Builtin { .. } => {
                    // Already handled above
                }
                RuleSource::RemoteUrl { name, .. } => {
                    // Remote URLs require async fetch; call load_remote_sources() after load_all()
                    info!(source = %name, "Remote source deferred — call load_remote_sources() to fetch");
                }
            }
        }

        {
            let mut reg = self.registry.write();
            reg.mark_loaded();
        }

        info!(
            rules_loaded = report.rules_loaded,
            sources = report.sources_loaded,
            "Rule manager load complete"
        );

        Ok(report)
    }

    /// Reload all rules (clear + `load_all`). Returns a diff report.
    pub fn reload(&mut self) -> Result<RuleReloadReport> {
        let before = {
            let reg = self.registry.read();
            reg.rules.keys().cloned().collect::<std::collections::HashSet<_>>()
        };

        let load_report = self.load_all()?;

        let after = {
            let reg = self.registry.read();
            reg.rules.keys().cloned().collect::<std::collections::HashSet<_>>()
        };

        let added = after.difference(&before).count();
        let removed = before.difference(&after).count();
        let unchanged = after.intersection(&before).count();

        Ok(RuleReloadReport {
            added,
            removed,
            unchanged,
            errors: load_report.errors,
        })
    }

    /// Validate a rule file and return any errors (empty = valid).
    pub fn validate_file(&self, path: &Path) -> Result<Vec<ValidationError>> {
        let format = RuleFormat::from_path(path)
            .ok_or_else(|| anyhow::anyhow!("Unknown rule format for: {}", path.display()))?;
        let content = std::fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
        Ok(validate_rules(&content, format))
    }

    /// Import rules from a local file.
    pub fn import_from_file(&mut self, path: &Path) -> Result<usize> {
        let format = RuleFormat::from_path(path)
            .ok_or_else(|| anyhow::anyhow!("Unknown rule format for: {}", path.display()))?;
        let rules = load_file(path, format)?;
        let count = rules.len();
        {
            let mut reg = self.registry.write();
            for rule in rules {
                reg.insert(rule);
            }
        }
        Ok(count)
    }

    /// Import rules from a remote URL (async; requires a tokio runtime).
    ///
    /// Tries YAML then JSON parsers in order.  Use `import_from_url_with_format`
    /// when the remote content format is known ahead of time.
    pub async fn import_from_url(&mut self, url: &str) -> Result<usize> {
        let content = fetch_remote_content(url).await?;

        // Try YAML first, then JSON
        let rules = super::formats::yaml::parse(&content)
            .or_else(|_| super::formats::json::parse(&content))
            .with_context(|| format!("Failed to parse rules from {url}"))?;

        let count = rules.len();
        self.insert_rules(rules);
        info!(url, rules = count, "Imported rules from URL");
        Ok(count)
    }

    /// Import rules from a remote URL using the given format hint.
    ///
    /// Unlike `import_from_url`, this method uses the configured `format` to
    /// select the parser directly instead of falling back through YAML/JSON.
    pub async fn import_from_url_with_format(&mut self, url: &str, format: RuleFormat) -> Result<usize> {
        let content = fetch_remote_content(url).await?;

        let rules = parse_rules(&content, format)
            .with_context(|| format!("Failed to parse {} rules from {url}", format.as_str()))?;

        let count = rules.len();
        self.insert_rules(rules);
        info!(url, rules = count, format = format.as_str(), "Imported rules from URL");
        Ok(count)
    }

    /// Load all configured `RemoteUrl` sources asynchronously.
    ///
    /// Fetches and parses each `RemoteUrl` entry from `self.sources`, inserting
    /// the resulting rules into the registry.  This is the primary way to
    /// activate remote sources; it can be called standalone (e.g. `rules update`)
    /// or after `load_all()` when a full rule reload is needed.
    ///
    /// Returns one entry per remote source: `(name, result)`.  Failures do not
    /// abort the loop — every configured source is attempted regardless.
    pub async fn load_remote_sources(&mut self) -> Vec<(String, Result<usize>)> {
        // Collect metadata upfront to avoid simultaneous borrow of self.sources
        // and &mut self in import_from_url_with_format.
        let remote_meta: Vec<(String, String, RuleFormat)> = self
            .sources
            .iter()
            .filter_map(|s| {
                if let RuleSource::RemoteUrl { name, url, format, .. } = s {
                    Some((name.clone(), url.clone(), *format))
                } else {
                    None
                }
            })
            .collect();

        let mut results = Vec::with_capacity(remote_meta.len());
        for (name, url, format) in remote_meta {
            let result = self.import_from_url_with_format(&url, format).await;
            match &result {
                Ok(count) => info!(source = %name, count, "Loaded remote rule source"),
                Err(e) => warn!(source = %name, error = %e, "Failed to load remote rule source"),
            }
            results.push((name, result));
        }
        results
    }

    // ── Private insert helper ─────────────────────────────────────────────────

    fn insert_rules(&self, rules: Vec<Rule>) {
        let mut reg = self.registry.write();
        for rule in rules {
            reg.insert(rule);
        }
    }

    /// Export all enabled rules in the given format.
    pub fn export(&self, format: ExportFormat) -> Result<String> {
        let rules: Vec<Rule> = {
            let reg = self.registry.read();
            reg.list().into_iter().cloned().collect()
        };
        export_rules(&rules, format)
    }

    /// Search rules by name, id, or description.
    pub fn search(&self, query: &str) -> Vec<Rule> {
        let reg = self.registry.read();
        reg.search(query).into_iter().cloned().collect()
    }

    /// Enable a rule by id.
    pub fn enable_rule(&mut self, id: &str) -> Result<()> {
        let mut reg = self.registry.write();
        match reg.get_mut(id) {
            Some(rule) => {
                rule.enabled = true;
                Ok(())
            }
            None => bail!("Rule not found: {id}"),
        }
    }

    /// Disable a rule by id.
    pub fn disable_rule(&mut self, id: &str) -> Result<()> {
        let mut reg = self.registry.write();
        match reg.get_mut(id) {
            Some(rule) => {
                rule.enabled = false;
                Ok(())
            }
            None => bail!("Rule not found: {id}"),
        }
    }

    /// Return registry statistics.
    pub fn stats(&self) -> RuleStats {
        let reg = self.registry.read();
        reg.stats()
    }

    /// Get a shared handle to the registry (for the WAF engine pipeline).
    pub fn registry_handle(&self) -> Arc<RwLock<RuleRegistry>> {
        Arc::clone(&self.registry)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn load_from_dir(&self, dir: &Path) -> Result<RuleLoadReport> {
        let mut report = RuleLoadReport::default();
        if !dir.is_dir() {
            return Ok(report);
        }

        let entries = std::fs::read_dir(dir).with_context(|| format!("Cannot read rules dir: {}", dir.display()))?;

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(format) = RuleFormat::from_path(&path) else {
                continue; // skip unknown extensions
            };
            match load_file(&path, format) {
                Ok(rules) => {
                    let count = rules.len();
                    {
                        let mut reg = self.registry.write();
                        for rule in rules {
                            reg.insert(rule);
                        }
                    }
                    report.rules_loaded += count;
                    report.sources_loaded += 1;
                }
                Err(e) => {
                    warn!(path = %path.display(), "Failed to load rule file: {e}");
                    report.errors.push(format!("{}: {e}", path.display()));
                }
            }
        }

        Ok(report)
    }
}

/// Read and parse a single rule file.
fn load_file(path: &Path, format: RuleFormat) -> Result<Vec<Rule>> {
    let content = std::fs::read_to_string(path).with_context(|| format!("Cannot read {}", path.display()))?;
    parse_rules(&content, format).with_context(|| format!("Failed to parse {}", path.display()))
}

/// Maximum allowed response body size for remote rule sources (10 MiB).
const MAX_RULES_RESPONSE_SIZE: u64 = 10 * 1024 * 1024;

/// Fetch the text content of a remote URL with SSRF protection.
///
/// Safety measures applied:
/// - URL is validated against private/reserved IP ranges before fetching.
/// - The HTTP client is pinned to the IPs resolved at validation time via
///   `resolve_to_addrs`, closing the DNS-rebinding TOCTOU window.
/// - HTTP redirects are disabled to prevent redirect-based SSRF.
/// - A 30-second total timeout and 10-second connect timeout cap slow connections.
/// - Response body is capped at [`MAX_RULES_RESPONSE_SIZE`] to prevent OOM.
///
/// Returns the response body as a UTF-8 string.
async fn fetch_remote_content(url: &str) -> Result<String> {
    // Validate the URL against SSRF targets (private IPs, loopback, IMDS, etc.)
    // before opening any network connection.  The returned `validated_url` and
    // `resolved_addrs` are used below to pin the client and close the
    // DNS-rebinding TOCTOU gap.
    let (validated_url, resolved_addrs) = waf_common::url_validator::validate_public_url_with_ips(url)
        .with_context(|| format!("Remote rule URL failed SSRF validation: {url}"))?;

    let mut builder = reqwest::Client::builder()
        // Disable all redirects — a redirect could point to an internal endpoint.
        .redirect(reqwest::redirect::Policy::none())
        // Total request timeout (connect + read).
        .timeout(std::time::Duration::from_secs(30))
        // Connection establishment timeout only.
        .connect_timeout(std::time::Duration::from_secs(10));

    // Pin the client to the IPs validated above.  Only applies when the URL
    // contains a DNS hostname; IP-literal URLs return an empty `resolved_addrs`.
    // Re-use the already-parsed `validated_url` to extract the host, avoiding
    // a redundant parse and removing the need to import `url` directly in this
    // crate.
    if !resolved_addrs.is_empty()
        && let Some(host) = validated_url.host_str()
    {
        builder = builder.resolve_to_addrs(host, &resolved_addrs);
    }

    let client = builder
        .build()
        .with_context(|| "Failed to build SSRF-safe HTTP client")?;

    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("Failed to fetch {url}"))?;

    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("Remote source returned HTTP {status} for {url}");
    }

    // Reject responses that advertise a body larger than the cap.
    if let Some(len) = response.content_length()
        && len > MAX_RULES_RESPONSE_SIZE
    {
        anyhow::bail!("Remote rules response too large: {len} bytes (max {MAX_RULES_RESPONSE_SIZE})");
    }

    let body = response
        .text()
        .await
        .with_context(|| format!("Failed to read response body from {url}"))?;

    // Double-check the actual body length after download (Content-Length may be absent).
    if body.len() as u64 > MAX_RULES_RESPONSE_SIZE {
        anyhow::bail!(
            "Remote rules body too large: {} bytes (max {MAX_RULES_RESPONSE_SIZE})",
            body.len()
        );
    }

    Ok(body)
}
