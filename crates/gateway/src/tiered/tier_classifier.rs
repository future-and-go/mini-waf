//! Tier classifier — first-match-wins lookup over compiled rules.
//!
//! Borrowed `RequestParts` view keeps the classifier free of Pingora types
//! so unit tests don't need a session. Phase 5 builds `RequestParts` from
//! a Pingora request at the start of the request lifecycle.

use http::{HeaderMap, Method};
use waf_common::tier::{Tier, TierClassifierRule};

use crate::tiered::compiled_rule::{CompileError, CompiledTierRule, compile_rules};

/// Borrowed view over the request fields the classifier reads.
/// `host` is expected lowercased once by the caller.
#[derive(Debug)]
pub struct RequestParts<'a> {
    pub host: &'a str,
    pub path: &'a str,
    pub method: &'a Method,
    pub headers: &'a HeaderMap,
}

#[derive(Debug)]
pub struct TierClassifier {
    rules: Vec<CompiledTierRule>,
    default_tier: Tier,
}

impl TierClassifier {
    /// Build classifier from raw rules + default tier. Rules are
    /// pre-compiled (regex, header parse) and sorted by priority DESC.
    pub fn new(rules: &[TierClassifierRule], default_tier: Tier) -> Result<Self, CompileError> {
        Ok(Self {
            rules: compile_rules(rules)?,
            default_tier,
        })
    }

    pub const fn default_tier(&self) -> Tier {
        self.default_tier
    }

    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Classify a request. O(rules); first match wins. Falls back to default tier.
    pub fn classify(&self, req: &RequestParts<'_>) -> Tier {
        for r in &self.rules {
            if r.matches(req.host, req.path, req.method, req.headers) {
                return r.tier;
            }
        }
        self.default_tier
    }
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue, Method};
    use waf_common::tier::{HttpMethod, Tier, TierClassifierRule};
    use waf_common::tier_match::{HeaderMatch, HostMatch, PathMatch};

    use super::{RequestParts, TierClassifier};

    fn rule(priority: u32, tier: Tier) -> TierClassifierRule {
        TierClassifierRule {
            priority,
            tier,
            host: None,
            path: None,
            method: None,
            headers: None,
        }
    }

    fn parts<'a>(host: &'a str, path: &'a str, method: &'a Method, headers: &'a HeaderMap) -> RequestParts<'a> {
        RequestParts {
            host,
            path,
            method,
            headers,
        }
    }

    #[test]
    fn priority_higher_wins_when_multiple_match() {
        let mut low = rule(10, Tier::Medium);
        low.path = Some(PathMatch::Prefix { value: "/api".into() });
        let mut high = rule(100, Tier::Critical);
        high.path = Some(PathMatch::Prefix { value: "/api".into() });

        let c = TierClassifier::new(&[low, high], Tier::CatchAll).unwrap();
        let h = HeaderMap::new();
        assert_eq!(c.classify(&parts("x", "/api/v1", &Method::GET, &h)), Tier::Critical);
    }

    #[test]
    fn default_tier_when_no_match() {
        let mut r = rule(10, Tier::High);
        r.path = Some(PathMatch::Exact { value: "/admin".into() });
        let c = TierClassifier::new(&[r], Tier::CatchAll).unwrap();
        let h = HeaderMap::new();
        assert_eq!(c.classify(&parts("x", "/public", &Method::GET, &h)), Tier::CatchAll);
    }

    #[test]
    fn path_exact_prefix_regex_each_match() {
        let mut exact = rule(30, Tier::Critical);
        exact.path = Some(PathMatch::Exact { value: "/login".into() });
        let mut prefix = rule(20, Tier::High);
        prefix.path = Some(PathMatch::Prefix { value: "/api/".into() });
        let mut re = rule(10, Tier::Medium);
        re.path = Some(PathMatch::Regex {
            value: r"^/users/\d+$".into(),
        });

        let c = TierClassifier::new(&[exact, prefix, re], Tier::CatchAll).unwrap();
        let h = HeaderMap::new();
        assert_eq!(c.classify(&parts("h", "/login", &Method::GET, &h)), Tier::Critical);
        assert_eq!(c.classify(&parts("h", "/api/v1", &Method::GET, &h)), Tier::High);
        assert_eq!(c.classify(&parts("h", "/users/42", &Method::GET, &h)), Tier::Medium);
        assert_eq!(c.classify(&parts("h", "/users/abc", &Method::GET, &h)), Tier::CatchAll);
    }

    #[test]
    fn host_suffix_match() {
        let mut r = rule(10, Tier::High);
        r.host = Some(HostMatch::Suffix {
            value: ".example.com".into(),
        });
        let c = TierClassifier::new(&[r], Tier::CatchAll).unwrap();
        let h = HeaderMap::new();
        assert_eq!(c.classify(&parts("api.example.com", "/", &Method::GET, &h)), Tier::High);
        assert_eq!(c.classify(&parts("other.org", "/", &Method::GET, &h)), Tier::CatchAll);
    }

    #[test]
    fn method_bitset_match() {
        let mut r = rule(10, Tier::Critical);
        r.method = Some(vec![HttpMethod::Post, HttpMethod::Delete]);
        let c = TierClassifier::new(&[r], Tier::CatchAll).unwrap();
        let h = HeaderMap::new();
        assert_eq!(c.classify(&parts("h", "/", &Method::POST, &h)), Tier::Critical);
        assert_eq!(c.classify(&parts("h", "/", &Method::DELETE, &h)), Tier::Critical);
        assert_eq!(c.classify(&parts("h", "/", &Method::GET, &h)), Tier::CatchAll);
    }

    #[test]
    fn header_match_exact() {
        let mut r = rule(10, Tier::High);
        r.headers = Some(vec![HeaderMatch {
            name: "X-API-Key".into(),
            value: "secret".into(),
        }]);
        let c = TierClassifier::new(&[r], Tier::CatchAll).unwrap();

        let mut h = HeaderMap::new();
        h.insert("x-api-key", HeaderValue::from_static("secret"));
        assert_eq!(c.classify(&parts("h", "/", &Method::GET, &h)), Tier::High);

        let mut wrong = HeaderMap::new();
        wrong.insert("x-api-key", HeaderValue::from_static("other"));
        assert_eq!(c.classify(&parts("h", "/", &Method::GET, &wrong)), Tier::CatchAll);

        let none = HeaderMap::new();
        assert_eq!(c.classify(&parts("h", "/", &Method::GET, &none)), Tier::CatchAll);
    }

    #[test]
    fn combined_path_method_must_all_match() {
        let mut r = rule(10, Tier::Critical);
        r.path = Some(PathMatch::Prefix { value: "/admin".into() });
        r.method = Some(vec![HttpMethod::Post]);
        let c = TierClassifier::new(&[r], Tier::CatchAll).unwrap();
        let h = HeaderMap::new();

        assert_eq!(c.classify(&parts("h", "/admin/x", &Method::POST, &h)), Tier::Critical);
        // path matches but method does not → AND fails
        assert_eq!(c.classify(&parts("h", "/admin/x", &Method::GET, &h)), Tier::CatchAll);
        // method matches but path does not
        assert_eq!(c.classify(&parts("h", "/public", &Method::POST, &h)), Tier::CatchAll);
    }

    #[test]
    fn random_rule_sets_classify_without_panic() {
        // Lightweight property-style test: deterministic pseudo-random rule set
        // that exercises every matcher kind across many requests.
        let kinds = [Tier::Critical, Tier::High, Tier::Medium, Tier::CatchAll];
        let mut rules = Vec::new();
        for i in 0..20u32 {
            let tier = kinds.get((i as usize) % kinds.len()).copied().unwrap_or(Tier::CatchAll);
            let mut r = rule(i, tier);
            match i % 4 {
                0 => {
                    r.path = Some(PathMatch::Prefix {
                        value: format!("/p{i}"),
                    });
                }
                1 => {
                    r.path = Some(PathMatch::Regex {
                        value: format!("^/r{i}/[0-9]+$"),
                    });
                }
                2 => {
                    r.host = Some(HostMatch::Suffix {
                        value: format!(".d{i}.com"),
                    });
                }
                _ => r.method = Some(vec![HttpMethod::Get, HttpMethod::Post]),
            }
            rules.push(r);
        }
        let c = TierClassifier::new(&rules, Tier::CatchAll).unwrap();
        let h = HeaderMap::new();
        for i in 0..1000u32 {
            let path = format!("/p{}/x", i % 25);
            let host = format!("x.d{}.com", i % 25);
            // Should never panic regardless of inputs.
            let _ = c.classify(&parts(&host, &path, &Method::GET, &h));
        }
    }

    #[test]
    fn bad_regex_surfaces_compile_error() {
        let mut r = rule(10, Tier::High);
        r.path = Some(PathMatch::Regex { value: "(".into() });
        assert!(TierClassifier::new(&[r], Tier::CatchAll).is_err());
    }
}
