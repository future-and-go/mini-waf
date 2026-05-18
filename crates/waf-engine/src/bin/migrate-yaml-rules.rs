//! Migrate Registry-format YAML rules to `custom_rule_v1` multi-document YAML.
//!
//! Reads each `.yaml` file under the specified directories, parses the
//! `{version, rules: [...]}` wrapper, converts every rule to `custom_rule_v1`
//! output, and writes the result back to the same file path.
//!
//! Usage: `cargo run --bin migrate-yaml-rules -- rules/`

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::{env, fs, process};

use serde::{Deserialize, Serialize};

// ── Source format (Registry wrapper) ──────────────────────────────────

/// Top-level wrapper found in registry YAML files.
/// Fields like `version`, `description`, `license` are only consumed by serde.
#[derive(Debug, Deserialize, Default)]
#[allow(dead_code)]
struct RegistryWrapper {
    #[serde(default)]
    version: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    source: String,
    #[serde(default)]
    license: String,
    rules: Vec<RegistryRule>,
}

/// A single rule inside the registry wrapper.
#[derive(Debug, Deserialize)]
struct RegistryRule {
    id: String,
    name: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    paranoia: Option<u8>,
    #[serde(default)]
    field: String,
    #[serde(default)]
    operator: String,
    #[serde(default)]
    value: Option<serde_yaml::Value>,
    #[serde(default)]
    action: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    risk_delta: Option<i16>,
    #[serde(default)]
    risk_action: Option<String>,
    #[serde(default)]
    reference: Option<String>,
    #[serde(default)]
    crs_id: Option<u32>,
    #[serde(default)]
    metadata: HashMap<String, String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    pattern: Option<String>,
}

// ── Target format (custom_rule_v1 output) ─────────────────────────────

/// Output rule matching the `custom_rule_v1` schema.
#[derive(Debug, Serialize)]
struct OutputRule {
    kind: String,
    id: String,
    name: String,
    #[serde(skip_serializing_if = "is_wildcard")]
    host_code: String,
    #[serde(skip_serializing_if = "is_zero")]
    priority: i32,
    enabled: bool,
    action: String,
    // Regex pattern path
    #[serde(skip_serializing_if = "Option::is_none")]
    pattern: Option<String>,
    #[serde(skip_serializing_if = "is_default_field")]
    pattern_field: String,
    // Non-regex operator shorthand (auto-converted by parser)
    #[serde(skip_serializing_if = "Option::is_none")]
    operator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<serde_yaml::Value>,
    // Metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    paranoia: Option<u8>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    risk_delta: Option<i16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    risk_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reference: Option<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    metadata: HashMap<String, String>,
}

fn is_wildcard(s: &str) -> bool {
    s == "*"
}
fn is_zero(n: &i32) -> bool {
    *n == 0
}
fn is_default_field(s: &str) -> bool {
    s == "all"
}

// ── Conversion ────────────────────────────────────────────────────────

fn convert_rule(r: RegistryRule, wrapper_source: &str) -> OutputRule {
    let is_regex = r.operator == "regex" || r.operator.is_empty();

    // Determine pattern vs operator shorthand:
    // - regex / empty operator → pattern field (the engine's native regex path)
    // - pm_from_file → operator shorthand (engine has special handling)
    // - all others → operator shorthand (auto-converted to Condition by parser)
    let (pattern, operator, value) = if is_regex {
        // Regex rules: value becomes the pattern string
        let pat = r
            .pattern
            .or_else(|| r.value.as_ref().and_then(|v| v.as_str().map(String::from)));
        // Fix Rust-incompatible regex: bare \0 (PCRE null) → \x00.
        // Only replace \0 NOT already followed by a hex digit (avoid clobbering \0a etc).
        let pat = pat.map(|p| {
            let mut result = String::with_capacity(p.len());
            let chars: Vec<char> = p.chars().collect();
            let mut i = 0;
            while i < chars.len() {
                if chars[i] == '\\'
                    && chars.get(i + 1) == Some(&'0')
                    && chars.get(i + 2).map_or(true, |c| !c.is_ascii_digit())
                {
                    result.push_str("\\x00");
                    i += 2;
                } else {
                    result.push(chars[i]);
                    i += 1;
                }
            }
            result
        });
        (pat, None, None)
    } else {
        // Normalize operator aliases
        let op = match r.operator.as_str() {
            "equals" => "eq".to_string(),
            other => other.to_string(),
        };
        (None, Some(op), r.value)
    };

    let mut metadata = r.metadata;
    if let Some(crs_id) = r.crs_id {
        metadata.insert("crs_id".to_string(), crs_id.to_string());
    }
    if !wrapper_source.is_empty() {
        metadata
            .entry("source".to_string())
            .or_insert_with(|| wrapper_source.to_string());
    }
    if let Some(desc) = r.description {
        if !desc.is_empty() {
            metadata.entry("description".to_string()).or_insert(desc);
        }
    }

    OutputRule {
        kind: "custom_rule_v1".to_string(),
        id: r.id,
        name: r.name,
        host_code: "*".to_string(),
        priority: 0,
        enabled: r.enabled.unwrap_or(true),
        action: if r.action.is_empty() {
            "block".to_string()
        } else {
            r.action
        },
        pattern,
        pattern_field: if r.field.is_empty() { "all".to_string() } else { r.field },
        operator,
        value,
        category: if r.category.is_empty() { None } else { Some(r.category) },
        severity: if r.severity.is_empty() { None } else { Some(r.severity) },
        paranoia: r.paranoia,
        tags: r.tags,
        risk_delta: r.risk_delta,
        risk_action: r.risk_action,
        reference: r.reference,
        metadata,
    }
}

// ── Stats tracking ────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct Stats {
    files: usize,
    rules_before: usize,
    rules_after: usize,
    skipped: usize,
    errors: Vec<String>,
}

// ── Directory walker ──────────────────────────────────────────────────

/// Directories to migrate (relative to the rules root).
const MIGRATE_DIRS: &[&str] = &["advanced", "owasp-crs", "cve-patches", "bot-detection"];

fn collect_yaml_files(rules_root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for dir_name in MIGRATE_DIRS {
        let dir = rules_root.join(dir_name);
        if !dir.is_dir() {
            eprintln!("WARN: directory not found: {}", dir.display());
            continue;
        }
        let Ok(entries) = fs::read_dir(&dir) else {
            eprintln!("WARN: cannot read directory: {}", dir.display());
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("yaml") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

// ── File migration ────────────────────────────────────────────────────

fn migrate_file(path: &Path, stats: &mut Stats) -> Result<(), String> {
    let content = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;

    // Try wrapper format first (has `rules:` key)
    let wrapper: RegistryWrapper = if content.contains("rules:") {
        serde_yaml::from_str(&content).map_err(|e| format!("parse wrapper {}: {e}", path.display()))?
    } else {
        // Try flat array format (bare list of rules)
        let rules: Vec<RegistryRule> =
            serde_yaml::from_str(&content).map_err(|e| format!("parse flat {}: {e}", path.display()))?;
        RegistryWrapper {
            rules,
            ..Default::default()
        }
    };

    let rules_before = wrapper.rules.len();
    if rules_before == 0 {
        stats.skipped += 1;
        return Ok(());
    }

    let mut output = String::new();
    let mut rules_after = 0_usize;

    for rule in wrapper.rules {
        let converted = convert_rule(rule, &wrapper.source);
        let doc = serde_yaml::to_string(&converted).map_err(|e| format!("serialize {}: {e}", path.display()))?;

        if !output.is_empty() {
            output.push_str("---\n");
        }
        output.push_str(&doc);
        rules_after += 1;
    }

    fs::write(path, &output).map_err(|e| format!("write {}: {e}", path.display()))?;

    stats.files += 1;
    stats.rules_before += rules_before;
    stats.rules_after += rules_after;

    Ok(())
}

// ── Validation ────────────────────────────────────────────────────────

struct ValidationResult {
    total_rules: usize,
    warnings: Vec<String>,
    errors: Vec<String>,
}

fn validate_migrated_files(rules_root: &Path) -> ValidationResult {
    let files = collect_yaml_files(rules_root);
    let mut result = ValidationResult {
        total_rules: 0,
        warnings: Vec::new(),
        errors: Vec::new(),
    };

    for path in &files {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                result.errors.push(format!("read {}: {e}", path.display()));
                continue;
            }
        };

        match waf_engine::rules::formats::custom_rule_yaml::parse(&content) {
            Ok(rules) => {
                if rules.is_empty() {
                    result.errors.push(format!("{}: parsed 0 rules", path.display()));
                    continue;
                }
                result.total_rules += rules.len();
            }
            Err(e) => {
                let msg = format!("{e:#}");
                // Regex compilation failures are pre-existing issues (PCRE patterns
                // incompatible with Rust's regex crate). Warn but don't block.
                if msg.contains("invalid pattern regex") || msg.contains("regex") {
                    result.warnings.push(format!("{}: {msg}", path.display()));
                    // Count rules by scanning for "kind:" lines as fallback
                    result.total_rules += content.matches("kind: custom_rule_v1").count();
                } else {
                    result.errors.push(format!("{}: {msg}", path.display()));
                }
            }
        }
    }

    result
}

// ── Main ──────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = env::args().collect();
    let rules_root = match args.get(1) {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("Usage: migrate-yaml-rules <rules-directory>");
            eprintln!("Example: cargo run --bin migrate-yaml-rules -- rules/");
            process::exit(1);
        }
    };

    if !rules_root.is_dir() {
        eprintln!("ERROR: not a directory: {}", rules_root.display());
        process::exit(1);
    }

    // Phase 1: Migrate
    eprintln!("=== Migrating Registry YAML → custom_rule_v1 ===");
    let yaml_files = collect_yaml_files(&rules_root);
    eprintln!("Found {} YAML files to migrate", yaml_files.len());

    let mut stats = Stats::default();
    for path in &yaml_files {
        if let Err(e) = migrate_file(path, &mut stats) {
            eprintln!("ERROR: {e}");
            stats.errors.push(e);
        }
    }

    eprintln!();
    eprintln!("--- Migration Results ---");
    eprintln!("Files migrated:  {}", stats.files);
    eprintln!("Files skipped:   {}", stats.skipped);
    eprintln!("Rules before:    {}", stats.rules_before);
    eprintln!("Rules after:     {}", stats.rules_after);
    eprintln!("Errors:          {}", stats.errors.len());

    if stats.rules_before != stats.rules_after {
        eprintln!(
            "WARNING: rule count mismatch! before={} after={}",
            stats.rules_before, stats.rules_after
        );
    }

    // Phase 2: Validate
    eprintln!();
    eprintln!("=== Validating migrated files with custom_rule_yaml::parse() ===");
    let validation = validate_migrated_files(&rules_root);

    if !validation.warnings.is_empty() {
        eprintln!("WARNINGS (pre-existing regex compatibility issues):");
        for w in &validation.warnings {
            eprintln!("  - {w}");
        }
    }

    if !validation.errors.is_empty() {
        eprintln!("VALIDATION ERRORS:");
        for e in &validation.errors {
            eprintln!("  - {e}");
        }
        process::exit(1);
    }

    eprintln!("Validated {} rules across all files", validation.total_rules);
    if validation.total_rules != stats.rules_after {
        eprintln!(
            "WARNING: validation counted {} rules but migration wrote {}",
            validation.total_rules, stats.rules_after
        );
    }

    if !stats.errors.is_empty() {
        eprintln!();
        eprintln!("Migration completed with errors:");
        for e in &stats.errors {
            eprintln!("  - {e}");
        }
        process::exit(1);
    }

    eprintln!();
    eprintln!("Migration complete. Review with: git diff rules/");
}
