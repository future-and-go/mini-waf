//! Rule registry — in-memory store for all loaded WAF rules.

use std::collections::HashMap;
use std::time::Instant;

use serde::{Deserialize, Serialize};

/// A single WAF rule entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    /// Category: sqli | xss | rce | traversal | scanner | bot | access-control | custom | …
    pub category: String,
    /// Source identifier: owasp | builtin-bot | builtin-scanner | custom | file | …
    pub source: String,
    pub enabled: bool,
    /// Action: block | log | allow
    pub action: String,
    /// Severity: low | medium | high | critical
    pub severity: Option<String>,
    /// Optional regex pattern associated with the rule
    pub pattern: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Global rule registry with versioning.
///
/// Provides O(1) lookup by id and O(n) filtering by category/source.
/// `version` increments on every insert or remove so callers can detect stale snapshots.
#[derive(Default)]
pub struct RuleRegistry {
    pub rules: HashMap<String, Rule>,
    /// category → list of rule ids
    pub by_category: HashMap<String, Vec<String>>,
    /// source → list of rule ids
    pub by_source: HashMap<String, Vec<String>>,
    /// Monotonically increasing version counter
    pub version: u64,
    pub loaded_at: Option<Instant>,
}

impl RuleRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert (or replace) a rule.
    pub fn insert(&mut self, rule: Rule) {
        let id = rule.id.clone();
        // Remove old index entries if replacing
        if self.rules.contains_key(&id) {
            self.remove_index(&id);
        }
        self.by_category
            .entry(rule.category.clone())
            .or_default()
            .push(id.clone());
        self.by_source.entry(rule.source.clone()).or_default().push(id.clone());
        self.rules.insert(id, rule);
        self.version += 1;
    }

    /// Remove a rule by id. Returns the removed rule if it existed.
    pub fn remove(&mut self, id: &str) -> Option<Rule> {
        let rule = self.rules.remove(id)?;
        self.remove_index(id);
        self.version += 1;
        Some(rule)
    }

    fn remove_index(&mut self, id: &str) {
        for ids in self.by_category.values_mut() {
            ids.retain(|x| x != id);
        }
        for ids in self.by_source.values_mut() {
            ids.retain(|x| x != id);
        }
    }

    pub fn get(&self, id: &str) -> Option<&Rule> {
        self.rules.get(id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut Rule> {
        self.rules.get_mut(id)
    }

    /// Return all rules sorted by id.
    pub fn list(&self) -> Vec<&Rule> {
        let mut rules: Vec<&Rule> = self.rules.values().collect();
        rules.sort_by(|a, b| a.id.cmp(&b.id));
        rules
    }

    pub fn filter_by_category(&self, category: &str) -> Vec<&Rule> {
        self.by_category
            .get(category)
            .map(|ids| ids.iter().filter_map(|id| self.rules.get(id)).collect())
            .unwrap_or_default()
    }

    pub fn filter_by_source(&self, source: &str) -> Vec<&Rule> {
        self.by_source
            .get(source)
            .map(|ids| ids.iter().filter_map(|id| self.rules.get(id)).collect())
            .unwrap_or_default()
    }

    /// Case-insensitive search across id, name, description, category.
    pub fn search(&self, query: &str) -> Vec<&Rule> {
        let q = query.to_lowercase();
        self.rules
            .values()
            .filter(|r| {
                r.id.to_lowercase().contains(&q)
                    || r.name.to_lowercase().contains(&q)
                    || r.description.as_deref().is_some_and(|d| d.to_lowercase().contains(&q))
                    || r.category.to_lowercase().contains(&q)
            })
            .collect()
    }

    /// Compute registry statistics.
    pub fn stats(&self) -> RuleStats {
        let total = self.rules.len();
        let enabled = self.rules.values().filter(|r| r.enabled).count();
        let mut by_category: HashMap<String, usize> = HashMap::new();
        let mut by_source: HashMap<String, usize> = HashMap::new();
        for rule in self.rules.values() {
            *by_category.entry(rule.category.clone()).or_default() += 1;
            *by_source.entry(rule.source.clone()).or_default() += 1;
        }
        RuleStats {
            total,
            enabled,
            disabled: total - enabled,
            by_category,
            by_source,
            version: self.version,
        }
    }

    /// Clear all rules and reset version.
    pub fn clear(&mut self) {
        self.rules.clear();
        self.by_category.clear();
        self.by_source.clear();
        self.version = 0;
        self.loaded_at = None;
    }

    pub fn mark_loaded(&mut self) {
        self.loaded_at = Some(Instant::now());
    }
}

/// Statistics snapshot of the rule registry.
#[derive(Debug, Clone, Serialize)]
pub struct RuleStats {
    pub total: usize,
    pub enabled: usize,
    pub disabled: usize,
    pub by_category: HashMap<String, usize>,
    pub by_source: HashMap<String, usize>,
    pub version: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, category: &str, source: &str) -> Rule {
        Rule {
            id: id.to_string(),
            name: format!("name-{id}"),
            description: Some(format!("desc-{id}")),
            category: category.to_string(),
            source: source.to_string(),
            enabled: true,
            action: "block".to_string(),
            severity: None,
            pattern: None,
            tags: vec![],
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn insert_and_get_round_trip_bumps_version() {
        let mut reg = RuleRegistry::new();
        assert_eq!(reg.version, 0);
        reg.insert(rule("R1", "sqli", "owasp"));
        assert_eq!(reg.version, 1);
        let got = reg.get("R1").expect("present");
        assert_eq!(got.id, "R1");
        assert!(reg.get("missing").is_none());
    }

    #[test]
    fn insert_replacing_existing_rule_does_not_duplicate_index() {
        let mut reg = RuleRegistry::new();
        reg.insert(rule("R1", "sqli", "owasp"));
        // Replace with same id but new category/source.
        reg.insert(rule("R1", "xss", "custom"));
        assert_eq!(reg.rules.len(), 1);
        assert_eq!(reg.filter_by_category("sqli").len(), 0);
        assert_eq!(reg.filter_by_category("xss").len(), 1);
        assert_eq!(reg.filter_by_source("owasp").len(), 0);
        assert_eq!(reg.filter_by_source("custom").len(), 1);
    }

    #[test]
    fn remove_returns_rule_when_present_and_none_otherwise() {
        let mut reg = RuleRegistry::new();
        reg.insert(rule("R1", "sqli", "owasp"));
        let removed = reg.remove("R1").expect("removed");
        assert_eq!(removed.id, "R1");
        assert!(reg.get("R1").is_none());
        assert!(reg.remove("nope").is_none());
    }

    #[test]
    fn list_returns_rules_sorted_by_id() {
        let mut reg = RuleRegistry::new();
        reg.insert(rule("B", "c", "s"));
        reg.insert(rule("A", "c", "s"));
        reg.insert(rule("C", "c", "s"));
        let ids: Vec<_> = reg.list().into_iter().map(|r| r.id.clone()).collect();
        assert_eq!(ids, vec!["A", "B", "C"]);
    }

    #[test]
    fn filter_by_unknown_key_returns_empty() {
        let reg = RuleRegistry::new();
        assert!(reg.filter_by_category("nope").is_empty());
        assert!(reg.filter_by_source("nope").is_empty());
    }

    #[test]
    fn search_is_case_insensitive_across_fields() {
        let mut reg = RuleRegistry::new();
        reg.insert(rule("CRS-001", "sqli", "owasp"));
        reg.insert(rule("BOT-9", "bot", "builtin-bot"));

        assert_eq!(reg.search("crs").len(), 1);
        assert_eq!(reg.search("NAME-BOT-9").len(), 1);
        assert_eq!(reg.search("desc-bot").len(), 1);
        assert_eq!(reg.search("SQLI").len(), 1);
        assert!(reg.search("absent").is_empty());
    }

    #[test]
    fn stats_counts_enabled_disabled_and_groups() {
        let mut reg = RuleRegistry::new();
        let mut a = rule("A", "sqli", "owasp");
        a.enabled = false;
        reg.insert(a);
        reg.insert(rule("B", "sqli", "owasp"));
        reg.insert(rule("C", "xss", "custom"));

        let s = reg.stats();
        assert_eq!(s.total, 3);
        assert_eq!(s.enabled, 2);
        assert_eq!(s.disabled, 1);
        assert_eq!(s.by_category.get("sqli").copied(), Some(2));
        assert_eq!(s.by_category.get("xss").copied(), Some(1));
        assert_eq!(s.by_source.get("owasp").copied(), Some(2));
        assert_eq!(s.by_source.get("custom").copied(), Some(1));
        assert_eq!(s.version, reg.version);
    }

    #[test]
    fn clear_resets_state() {
        let mut reg = RuleRegistry::new();
        reg.insert(rule("R1", "sqli", "owasp"));
        reg.mark_loaded();
        assert!(reg.loaded_at.is_some());
        reg.clear();
        assert_eq!(reg.rules.len(), 0);
        assert_eq!(reg.version, 0);
        assert!(reg.loaded_at.is_none());
        assert!(reg.by_category.is_empty());
        assert!(reg.by_source.is_empty());
    }

    #[test]
    fn get_mut_allows_in_place_modification() {
        let mut reg = RuleRegistry::new();
        reg.insert(rule("R1", "sqli", "owasp"));
        if let Some(r) = reg.get_mut("R1") {
            r.enabled = false;
        }
        assert!(!reg.get("R1").expect("present").enabled);
        assert!(reg.get_mut("missing").is_none());
    }
}
