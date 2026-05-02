//! User-Agent regex blocklist provider.
//!
//! Wraps a `regex::RegexSet` so matching is O(input) over all patterns at
//! once. Emits one `Signal::UaBlocklisted` per matched pattern (callers
//! typically dedupe at the aggregator). Patterns are validated on
//! construction:
//! - Each pattern source ≤ 10 KiB
//! - Reject patterns containing nested unbounded quantifiers like
//!   `(.*)*` (cheap `ReDoS` guard; the `regex` crate has linear matching
//!   but the compile cost can still spike).

use anyhow::{Context, bail};
use regex::RegexSet;

use crate::device_fp::providers::SignalProvider;
use crate::device_fp::signal::Signal;
use crate::device_fp::types::DeviceCtx;

const MAX_PATTERN_BYTES: usize = 10 * 1024;

#[derive(Debug)]
pub struct UaBlocklistProvider {
    set: RegexSet,
    patterns: Vec<String>,
}

impl Default for UaBlocklistProvider {
    fn default() -> Self {
        // RegexSet::empty() never fails — bypass the validator entirely
        // so Default cannot panic.
        Self {
            set: RegexSet::empty(),
            patterns: Vec::new(),
        }
    }
}

impl UaBlocklistProvider {
    /// Compile the patterns. Empty list is allowed and matches nothing.
    pub fn new(patterns: Vec<String>) -> anyhow::Result<Self> {
        for p in &patterns {
            validate_pattern(p)?;
        }
        let set = RegexSet::new(&patterns).context("ua_blocklist: compile RegexSet")?;
        Ok(Self { set, patterns })
    }

    #[must_use]
    pub const fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

fn validate_pattern(p: &str) -> anyhow::Result<()> {
    if p.len() > MAX_PATTERN_BYTES {
        bail!(
            "ua_blocklist: pattern exceeds {MAX_PATTERN_BYTES} bytes ({} given)",
            p.len()
        );
    }
    if p.contains("(.*)*") || p.contains("(.+)+") || p.contains("(.*)+") || p.contains("(.+)*") {
        bail!("ua_blocklist: pattern {p:?} has nested unbounded quantifier (ReDoS risk)");
    }
    Ok(())
}

impl SignalProvider for UaBlocklistProvider {
    fn name(&self) -> &'static str {
        "ua_blocklist"
    }
    fn evaluate(&self, ctx: &DeviceCtx<'_>) -> Vec<Signal> {
        if self.patterns.is_empty() {
            return Vec::new();
        }
        self.set
            .matches(ctx.user_agent)
            .into_iter()
            .filter_map(|i| {
                self.patterns
                    .get(i)
                    .map(|p| Signal::UaBlocklisted { pattern: p.clone() })
            })
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::trivially_copy_pass_by_ref)]
mod tests {
    use super::*;
    use crate::device_fp::capture::ConnCtx;
    use crate::device_fp::types::FpKey;
    use std::net::{IpAddr, Ipv4Addr};

    fn eval(p: &UaBlocklistProvider, ua: &str) -> Vec<Signal> {
        let conn = ConnCtx::new();
        let key = FpKey::default();
        let ctx = DeviceCtx::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ua, &conn, &key);
        p.evaluate(&ctx)
    }

    #[test]
    fn empty_patterns_no_signals() {
        let p = UaBlocklistProvider::new(Vec::new()).unwrap();
        assert!(eval(&p, "anything").is_empty());
    }

    #[test]
    fn matches_one_pattern() {
        let p = UaBlocklistProvider::new(vec![r"(?i)curl/".into(), r"(?i)wget".into()]).unwrap();
        let s = eval(&p, "curl/8.4.0");
        assert_eq!(s.len(), 1);
        assert!(matches!(&s[0], Signal::UaBlocklisted { pattern } if pattern.contains("curl")));
    }

    #[test]
    fn matches_multiple_patterns() {
        let p = UaBlocklistProvider::new(vec![r"(?i)bot".into(), r"crawler".into()]).unwrap();
        let s = eval(&p, "GoogleBot crawler/1.0");
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn no_match_clean_ua() {
        let p = UaBlocklistProvider::new(vec![r"(?i)curl".into()]).unwrap();
        assert!(eval(&p, "Mozilla/5.0").is_empty());
    }

    #[test]
    fn rejects_redos_pattern() {
        assert!(UaBlocklistProvider::new(vec![r"(.*)*foo".into()]).is_err());
    }

    #[test]
    fn rejects_oversize_pattern() {
        let big = "a".repeat(MAX_PATTERN_BYTES + 1);
        assert!(UaBlocklistProvider::new(vec![big]).is_err());
    }
}
