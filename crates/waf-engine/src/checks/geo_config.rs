//! Loader for the admin API's `configs/geo-rules.yaml`.
//!
//! The API persists flat per-row records (`{id, iso_code, action, scope,
//! enabled, country_name}`); the engine enforces [`GeoRule`]s grouped per
//! host. This module owns the mapping: rows are grouped by host (`scope:
//! "global"` → `"*"`), block rows union into one `Block` rule and allow rows
//! into one `AllowOnly` rule per host. One unioned `AllowOnly` rule is the
//! only correct mapping — separate per-row allow rules would each block every
//! visitor outside their single country.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::Context;
use tracing::info;

use super::geo::{GeoCheck, GeoRule, GeoRuleMode};

/// One row of the API file. `id`/`country_name` are UI concerns — optional
/// here so a hand-edited file cannot fail the load.
#[derive(Debug, Clone, serde::Deserialize)]
struct GeoRuleRow {
    iso_code: String,
    #[serde(default = "default_action")]
    action: String,
    #[serde(default = "default_scope")]
    scope: String,
    #[serde(default = "default_enabled")]
    enabled: bool,
}

fn default_action() -> String {
    "block".to_string()
}

fn default_scope() -> String {
    "global".to_string()
}

const fn default_enabled() -> bool {
    true
}

#[derive(Debug, serde::Deserialize)]
struct GeoRulesFile {
    #[serde(default)]
    rules: Vec<GeoRuleRow>,
}

/// Parse the API rules file into per-host engine rules.
///
/// Disabled rows are skipped. ISO codes are uppercased here so the grouping
/// sets are canonical (`GeoCheck::load_rules` uppercases again — harmless).
pub fn parse_geo_rules(path: &Path) -> anyhow::Result<HashMap<String, Vec<GeoRule>>> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("geo rules: read {}", path.display()))?;
    let file: GeoRulesFile =
        serde_yaml::from_str(&raw).with_context(|| format!("geo rules: parse {}", path.display()))?;

    // Per host: (block iso set, allow iso set)
    let mut hosts: HashMap<String, (HashSet<String>, HashSet<String>)> = HashMap::new();
    for row in file.rules {
        if !row.enabled {
            continue;
        }
        let host = if row.scope == "global" {
            "*".to_string()
        } else {
            row.scope
        };
        let iso = row.iso_code.to_ascii_uppercase();
        let entry = hosts.entry(host).or_default();
        if row.action == "allow" {
            entry.1.insert(iso);
        } else {
            entry.0.insert(iso);
        }
    }

    let mut out = HashMap::new();
    for (host, (block, allow)) in hosts {
        let mut rules = Vec::new();
        if !block.is_empty() {
            rules.push(GeoRule {
                id: format!("geo-{host}-block"),
                name: "Geo block".to_string(),
                mode: GeoRuleMode::Block,
                iso_codes: block,
                countries: HashSet::new(),
            });
        }
        if !allow.is_empty() {
            rules.push(GeoRule {
                id: format!("geo-{host}-allow"),
                name: "Geo allow-only".to_string(),
                mode: GeoRuleMode::AllowOnly,
                iso_codes: allow,
                countries: HashSet::new(),
            });
        }
        if !rules.is_empty() {
            out.insert(host, rules);
        }
    }
    Ok(out)
}

/// Parse `path` and replace the full rule set in `geo_check`.
///
/// Every host in the file is loaded; every previously-loaded host absent
/// from the file is cleared (so a deleted rule cannot survive until restart).
///
/// Errors (missing file, bad YAML) leave the existing rules untouched —
/// callers log and keep the previous snapshot.
pub fn apply_geo_rules(geo_check: &GeoCheck, path: &Path) -> anyhow::Result<()> {
    let map = parse_geo_rules(path)?;
    let previous = geo_check.loaded_hosts();
    let mut hosts = 0usize;
    let mut rule_count = 0usize;
    for (host, rules) in &map {
        hosts += 1;
        rule_count += rules.len();
        geo_check.load_rules(host, rules.clone());
    }
    for host in previous {
        if !map.contains_key(&host) {
            geo_check.clear_rules(&host);
        }
    }
    info!(file = %path.display(), hosts, rules = rule_count, "geo rules loaded");
    Ok(())
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_rules(dir: &tempfile::TempDir, yaml: &str) -> std::path::PathBuf {
        let path = dir.path().join("geo-rules.yaml");
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(yaml.as_bytes()).expect("write");
        path
    }

    #[test]
    fn block_row_maps_to_global_block_rule() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = write_rules(
            &dir,
            r#"
rules:
  - id: 1
    iso_code: "KP"
    action: "block"
    scope: "global"
    enabled: true
    country_name: "North Korea"
    created_at: "2026-07-05T00:00:00Z"
"#,
        );
        let map = parse_geo_rules(&path).expect("parse");
        let rules = map.get("*").expect("global host");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].mode, GeoRuleMode::Block);
        assert!(rules[0].iso_codes.contains("KP"));
    }

    #[test]
    fn block_rows_union_into_one_rule() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = write_rules(
            &dir,
            r#"
rules:
  - { id: 1, iso_code: "KP", action: "block", scope: "global", enabled: true }
  - { id: 2, iso_code: "ir", action: "block", scope: "global", enabled: true }
"#,
        );
        let map = parse_geo_rules(&path).expect("parse");
        let rules = map.get("*").expect("global host");
        assert_eq!(rules.len(), 1, "two block rows must union into one rule");
        assert!(rules[0].iso_codes.contains("KP"));
        assert!(
            rules[0].iso_codes.contains("IR"),
            "iso codes are uppercased at map time"
        );
    }

    #[test]
    fn allow_rows_union_into_single_allow_only_rule() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = write_rules(
            &dir,
            r#"
rules:
  - { id: 1, iso_code: "US", action: "allow", scope: "global", enabled: true }
  - { id: 2, iso_code: "CA", action: "allow", scope: "global", enabled: true }
"#,
        );
        let map = parse_geo_rules(&path).expect("parse");
        let rules = map.get("*").expect("global host");
        assert_eq!(rules.len(), 1, "allow rows must union into ONE AllowOnly rule");
        assert_eq!(rules[0].mode, GeoRuleMode::AllowOnly);
        assert_eq!(rules[0].iso_codes.len(), 2);
    }

    #[test]
    fn disabled_rows_are_skipped() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = write_rules(
            &dir,
            r#"
rules:
  - { id: 1, iso_code: "KP", action: "block", scope: "global", enabled: false }
"#,
        );
        let map = parse_geo_rules(&path).expect("parse");
        assert!(map.is_empty(), "disabled rows must not produce rules");
    }

    #[test]
    fn host_scope_maps_under_host_key() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = write_rules(
            &dir,
            r#"
rules:
  - { id: 1, iso_code: "KP", action: "block", scope: "example", enabled: true }
"#,
        );
        let map = parse_geo_rules(&path).expect("parse");
        assert!(map.contains_key("example"));
        assert!(!map.contains_key("*"));
    }

    #[test]
    fn missing_file_errors_and_empty_list_maps_empty() {
        let dir = tempfile::tempdir().expect("tmpdir");
        assert!(parse_geo_rules(&dir.path().join("absent.yaml")).is_err());

        let path = write_rules(&dir, "rules: []\n");
        let map = parse_geo_rules(&path).expect("parse");
        assert!(map.is_empty());
    }

    #[test]
    fn apply_clears_hosts_absent_from_new_file() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let check = GeoCheck::new();

        let path = write_rules(
            &dir,
            r#"
rules:
  - { id: 1, iso_code: "KP", action: "block", scope: "global", enabled: true }
  - { id: 2, iso_code: "CN", action: "block", scope: "example", enabled: true }
"#,
        );
        apply_geo_rules(&check, &path).expect("first load");
        let mut hosts = check.loaded_hosts();
        hosts.sort();
        assert_eq!(hosts, vec!["*".to_string(), "example".to_string()]);

        let path = write_rules(
            &dir,
            r#"
rules:
  - { id: 1, iso_code: "KP", action: "block", scope: "global", enabled: true }
"#,
        );
        apply_geo_rules(&check, &path).expect("second load");
        assert_eq!(
            check.loaded_hosts(),
            vec!["*".to_string()],
            "absent host must be cleared"
        );
    }

    #[test]
    fn apply_error_keeps_existing_rules() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let check = GeoCheck::new();
        let path = write_rules(
            &dir,
            r#"
rules:
  - { id: 1, iso_code: "KP", action: "block", scope: "global", enabled: true }
"#,
        );
        apply_geo_rules(&check, &path).expect("first load");

        let bad = write_rules(&dir, "rules: {not: a list}\n");
        assert!(apply_geo_rules(&check, &bad).is_err());
        assert_eq!(
            check.loaded_hosts(),
            vec!["*".to_string()],
            "rules must survive a bad load"
        );
    }
}
