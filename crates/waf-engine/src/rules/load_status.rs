//! Rule load status reporting — tracks which rules loaded successfully and
//! which failed, with structured reason strings for metrics/admin API.

use std::path::PathBuf;

use serde::Serialize;

/// Outcome of attempting to compile a single rule at load time.
pub enum RuleLoadStatus {
    /// Rule compiled and is ready for evaluation.
    Loaded { rule_id: String },
    /// Rule failed to compile and was excluded from the active set.
    Failed(RuleLoadFailure),
}

/// A rule that failed to load, with a stable reason string for metrics labels.
#[derive(Debug, Clone, Serialize)]
pub struct RuleLoadFailure {
    pub rule_id: String,
    pub file: PathBuf,
    pub reason: String,
}

/// Summary of a rule load cycle — how many loaded vs. failed.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RuleLoadReport {
    pub loaded: Vec<String>,
    pub failed: Vec<RuleLoadFailure>,
}

impl RuleLoadReport {
    pub fn record(&mut self, status: RuleLoadStatus) {
        match status {
            RuleLoadStatus::Loaded { rule_id } => self.loaded.push(rule_id),
            RuleLoadStatus::Failed(failure) => self.failed.push(failure),
        }
    }

    pub fn merge(&mut self, other: Self) {
        self.loaded.extend(other.loaded);
        self.failed.extend(other.failed);
    }
}

/// Map an anyhow error chain to a stable reason string suitable for metric
/// labels and admin API responses.
pub fn classify_error(err: &anyhow::Error) -> &'static str {
    let msg = err.to_string();
    let chain = format!("{err:#}");

    if msg.contains("not found") || chain.contains("not found") {
        return "missing_data_file";
    }
    if msg.contains("too large") || chain.contains("too large") {
        return "data_file_too_large";
    }
    if msg.contains("too many patterns") || chain.contains("too many patterns") {
        return "too_many_patterns";
    }
    if msg.contains("outside rules_root") || msg.contains("..") || chain.contains("path_traversal") {
        return "path_traversal";
    }
    if msg.contains("invalid regex") || chain.contains("invalid regex") {
        return "invalid_regex";
    }
    if msg.contains("invalid CIDR") || chain.contains("invalid CIDR") {
        return "invalid_cidr";
    }
    if msg.contains("unsupported operator") || chain.contains("unsupported operator") {
        return "unsupported_operator";
    }
    "parse_error"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_loaded() {
        let mut report = RuleLoadReport::default();
        report.record(RuleLoadStatus::Loaded { rule_id: "R1".into() });
        assert_eq!(report.loaded.len(), 1);
        assert!(report.failed.is_empty());
    }

    #[test]
    fn record_failed() {
        let mut report = RuleLoadReport::default();
        report.record(RuleLoadStatus::Failed(RuleLoadFailure {
            rule_id: "R2".into(),
            file: PathBuf::from("bad.yaml"),
            reason: "missing_data_file".into(),
        }));
        assert!(report.loaded.is_empty());
        assert_eq!(report.failed.len(), 1);
        assert_eq!(
            report.failed.first().expect("has one failure").reason,
            "missing_data_file"
        );
    }

    #[test]
    fn merge_combines_reports() {
        let mut a = RuleLoadReport::default();
        a.record(RuleLoadStatus::Loaded { rule_id: "R1".into() });
        let mut b = RuleLoadReport::default();
        b.record(RuleLoadStatus::Failed(RuleLoadFailure {
            rule_id: "R2".into(),
            file: PathBuf::from("x.yaml"),
            reason: "parse_error".into(),
        }));
        a.merge(b);
        assert_eq!(a.loaded.len(), 1);
        assert_eq!(a.failed.len(), 1);
    }

    #[test]
    fn classify_missing_data_file() {
        let err = anyhow::anyhow!("data file not found: /rules/data/missing.data");
        assert_eq!(classify_error(&err), "missing_data_file");
    }

    #[test]
    fn classify_too_large() {
        let err = anyhow::anyhow!("data file too large: 20000000 bytes (cap 10485760)");
        assert_eq!(classify_error(&err), "data_file_too_large");
    }

    #[test]
    fn classify_too_many_patterns() {
        let err = anyhow::anyhow!("too many patterns in file: 200000");
        assert_eq!(classify_error(&err), "too_many_patterns");
    }

    #[test]
    fn classify_path_traversal() {
        let err = anyhow::anyhow!("data file value must not contain '..': ../../etc/passwd");
        assert_eq!(classify_error(&err), "path_traversal");
    }

    #[test]
    fn classify_invalid_regex() {
        let err = anyhow::anyhow!("invalid regex: (unclosed");
        assert_eq!(classify_error(&err), "invalid_regex");
    }

    #[test]
    fn classify_invalid_cidr() {
        let err = anyhow::anyhow!("invalid CIDR: not-a-cidr");
        assert_eq!(classify_error(&err), "invalid_cidr");
    }

    #[test]
    fn classify_unsupported_operator() {
        let err = anyhow::anyhow!("unsupported operator/value combination: Eq / Number(42)");
        assert_eq!(classify_error(&err), "unsupported_operator");
    }

    #[test]
    fn classify_unknown_defaults_to_parse_error() {
        let err = anyhow::anyhow!("something completely unexpected");
        assert_eq!(classify_error(&err), "parse_error");
    }
}
