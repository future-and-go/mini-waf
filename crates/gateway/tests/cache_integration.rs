//! FR-009 Phase 5 — end-to-end cache pipeline tests.
//!
//! These exercise the full gate chain (`TierGate → MethodGate → AuthGate →
//! RouteRuleGate → UpstreamCcGate → TierDefaultGate`) through the public
//! `ResponseCache` surface. Per-gate logic lives in `cache::gates::*` inline
//! tests; this file is the audit trail that the gates compose correctly.
//!
//! Each test asserting an FR-009 acceptance criterion includes a `// FR-009 AC-N`
//! comment so reviewers can grep for the regression guard.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::redundant_clone,
    clippy::redundant_closure_for_method_calls,
    clippy::field_reassign_with_default,
    clippy::significant_drop_tightening,
    clippy::similar_names,
    clippy::unreadable_literal,
    clippy::approx_constant,
    clippy::doc_markdown
)]

use std::sync::Arc;

use bytes::Bytes;
use gateway::cache::config::{CacheConfigDoc, Defaults, MatchDoc, PathSpec, RuleDoc};
use gateway::cache::{CompiledRuleSet, ResponseCache, RuleSetHolder};
use waf_common::tier::{CachePolicy, HttpMethod, Tier};

const POLICY_AGGRESSIVE_300: CachePolicy = CachePolicy::Aggressive { ttl_seconds: 300 };
const POLICY_SHORT_30: CachePolicy = CachePolicy::ShortTtl { ttl_seconds: 30 };

// --- helpers -----------------------------------------------------------------

fn rule_doc(id: &str, prefix: &str, ttl: u32, tags: Vec<String>) -> RuleDoc {
    RuleDoc {
        id: id.into(),
        match_: MatchDoc {
            host: None,
            path: PathSpec::Prefix { prefix: prefix.into() },
            methods: None,
        },
        ttl_seconds: ttl,
        tags,
        allow_authenticated: false,
    }
}

fn cache_with(rules: Vec<RuleDoc>) -> Arc<ResponseCache> {
    let set = CompiledRuleSet::try_from_doc(CacheConfigDoc {
        version: 1,
        defaults: Defaults::default(),
        rules,
    })
    .expect("ruleset compiles");
    ResponseCache::with_rules(8, 60, 3600, RuleSetHolder::new(set))
}

#[allow(clippy::too_many_arguments)]
async fn put(
    c: &ResponseCache,
    method: &str,
    host: &str,
    path: &str,
    query: &str,
    cc: Option<&str>,
    tier: Tier,
    policy: &CachePolicy,
    has_auth: bool,
    has_cookie: bool,
) -> bool {
    let key = ResponseCache::make_key(method, host, path, query);
    c.put(
        key,
        host,
        path,
        200,
        vec![],
        Bytes::from("ok"),
        cc,
        tier,
        policy,
        has_auth,
        has_cookie,
    )
    .await
}

// --- Method gate -------------------------------------------------------------

// FR-009 AC: only GET/HEAD are cached. POST/PUT/DELETE/PATCH/OPTIONS bypass.
#[tokio::test]
async fn non_idempotent_methods_bypass_regardless_of_rule() {
    let c = cache_with(vec![rule_doc("any", "/", 600, vec!["t".into()])]);
    for method in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"] {
        let stored = put(
            &c,
            method,
            "h",
            "/x",
            "",
            Some("max-age=600"),
            Tier::Medium,
            &POLICY_AGGRESSIVE_300,
            false,
            false,
        )
        .await;
        assert!(!stored, "method {method} must bypass");
    }
}

// --- Route rule (full pipeline) ---------------------------------------------

#[tokio::test]
async fn first_matching_rule_wins() {
    // declaration order matters: /static/* comes before / catch-all
    let c = cache_with(vec![
        rule_doc("static", "/static/", 1800, vec!["asset".into()]),
        rule_doc("all", "/", 60, vec!["catchall".into()]),
    ]);
    assert!(
        put(
            &c,
            "GET",
            "h",
            "/static/app.js",
            "",
            None,
            Tier::Medium,
            &POLICY_AGGRESSIVE_300,
            false,
            false,
        )
        .await
    );
    let entry = c
        .get(&ResponseCache::make_key("GET", "h", "/static/app.js", ""), Tier::Medium)
        .await
        .expect("hit");
    assert_eq!(entry.max_age, 1800, "first rule (1800) wins over later catch-all (60)");
}

#[tokio::test]
async fn ttl_zero_rule_is_explicit_bypass() {
    let c = cache_with(vec![rule_doc("deny", "/admin", 0, vec!["adm".into()])]);
    let stored = put(
        &c,
        "GET",
        "h",
        "/admin/users",
        "",
        Some("max-age=600"),
        Tier::Medium,
        &POLICY_AGGRESSIVE_300,
        false,
        false,
    )
    .await;
    assert!(!stored);
    assert_eq!(c.stats().bypassed_explicit_deny, 1);
}

#[tokio::test]
async fn query_string_produces_distinct_cache_entries() {
    // Same path with different ?v= should not collide.
    let c = cache_with(vec![rule_doc("static", "/static/", 600, vec!["asset".into()])]);
    assert!(
        put(
            &c,
            "GET",
            "h",
            "/static/main.js",
            "v=abc",
            None,
            Tier::Medium,
            &POLICY_AGGRESSIVE_300,
            false,
            false,
        )
        .await
    );
    assert!(
        put(
            &c,
            "GET",
            "h",
            "/static/main.js",
            "v=def",
            None,
            Tier::Medium,
            &POLICY_AGGRESSIVE_300,
            false,
            false,
        )
        .await
    );
    assert_eq!(c.tag_index_size(), 2, "distinct queries → distinct keys");
}

#[tokio::test]
async fn method_restricted_rule_rejects_non_listed() {
    // Rule explicitly limited to GET only. HEAD must fall through to default.
    let c = cache_with(vec![RuleDoc {
        id: "get-only".into(),
        match_: MatchDoc {
            host: None,
            path: PathSpec::Prefix { prefix: "/p".into() },
            methods: Some(vec![HttpMethod::Get]),
        },
        ttl_seconds: 7200,
        tags: vec!["t".into()],
        allow_authenticated: false,
    }]);

    // GET → matches rule, TTL = 3600 (capped by max_ttl_secs = 3600).
    assert!(
        put(
            &c,
            "GET",
            "h",
            "/p/x",
            "",
            None,
            Tier::Medium,
            &POLICY_AGGRESSIVE_300,
            false,
            false,
        )
        .await
    );
    let g = c
        .get(&ResponseCache::make_key("GET", "h", "/p/x", ""), Tier::Medium)
        .await
        .expect("hit");
    assert_eq!(g.max_age, 3600);

    // HEAD → rule does NOT match → falls through to TierDefaultGate at policy default (300).
    assert!(
        put(
            &c,
            "HEAD",
            "h",
            "/p/y",
            "",
            None,
            Tier::Medium,
            &POLICY_AGGRESSIVE_300,
            false,
            false,
        )
        .await
    );
    let h = c
        .get(&ResponseCache::make_key("HEAD", "h", "/p/y", ""), Tier::Medium)
        .await
        .expect("hit");
    assert_eq!(h.max_age, 300, "HEAD falls through to tier default");
}

#[tokio::test]
async fn host_wildcard_matches_every_host() {
    let c = cache_with(vec![RuleDoc {
        id: "any-host".into(),
        match_: MatchDoc {
            host: Some("*".into()),
            path: PathSpec::Prefix { prefix: "/".into() },
            methods: None,
        },
        ttl_seconds: 900,
        tags: vec!["t".into()],
        allow_authenticated: false,
    }]);
    for host in ["a.example.com", "b.test", "anything"] {
        assert!(
            put(
                &c,
                "GET",
                host,
                "/x",
                "",
                None,
                Tier::Medium,
                &POLICY_AGGRESSIVE_300,
                false,
                false,
            )
            .await,
            "host {host} should hit wildcard rule"
        );
    }
}

#[tokio::test]
async fn host_exact_does_not_match_evil_suffix() {
    // FR-009: exact host match must NOT confuse `api.example.com` with
    // `api.example.com.evil.tld`. RouteRuleGate's HostMatcher::Exact uses
    // string equality, not endsWith.
    let c = cache_with(vec![RuleDoc {
        id: "api".into(),
        match_: MatchDoc {
            host: Some("api.example.com".into()),
            path: PathSpec::Prefix { prefix: "/".into() },
            methods: None,
        },
        ttl_seconds: 600,
        tags: vec!["api".into()],
        allow_authenticated: false,
    }]);
    // legit host → cached at rule TTL.
    assert!(
        put(
            &c,
            "GET",
            "api.example.com",
            "/x",
            "",
            None,
            Tier::Medium,
            &POLICY_AGGRESSIVE_300,
            false,
            false,
        )
        .await
    );
    let g = c
        .get(
            &ResponseCache::make_key("GET", "api.example.com", "/x", ""),
            Tier::Medium,
        )
        .await
        .expect("hit");
    assert_eq!(g.max_age, 600);

    // attacker host → rule does NOT match; falls to tier default (300).
    assert!(
        put(
            &c,
            "GET",
            "api.example.com.evil.tld",
            "/x",
            "",
            None,
            Tier::Medium,
            &POLICY_AGGRESSIVE_300,
            false,
            false,
        )
        .await
    );
    let g2 = c
        .get(
            &ResponseCache::make_key("GET", "api.example.com.evil.tld", "/x", ""),
            Tier::Medium,
        )
        .await
        .expect("hit");
    assert_eq!(g2.max_age, 300, "evil suffix must NOT inherit api rule TTL");
}

// --- Upstream Cache-Control --------------------------------------------------

#[tokio::test]
async fn upstream_no_cache_bypasses() {
    let c = cache_with(vec![]);
    let stored = put(
        &c,
        "GET",
        "h",
        "/x",
        "",
        Some("no-cache"),
        Tier::Medium,
        &POLICY_AGGRESSIVE_300,
        false,
        false,
    )
    .await;
    assert!(!stored);
}

#[tokio::test]
async fn upstream_private_bypasses() {
    let c = cache_with(vec![]);
    let stored = put(
        &c,
        "GET",
        "h",
        "/x",
        "",
        Some("private, max-age=600"),
        Tier::Medium,
        &POLICY_AGGRESSIVE_300,
        false,
        false,
    )
    .await;
    assert!(!stored);
}

// --- Tier defaults -----------------------------------------------------------

#[tokio::test]
async fn high_tier_short_ttl_uses_30s_default() {
    // FR-009 AC: HIGH-tier policy `ShortTtl(30)` → cached at 30s when no
    // upstream Cache-Control and no matching rule.
    let c = cache_with(vec![]);
    assert!(
        put(
            &c,
            "GET",
            "h",
            "/x",
            "",
            None,
            Tier::High,
            &POLICY_SHORT_30,
            false,
            false,
        )
        .await
    );
    let entry = c
        .get(&ResponseCache::make_key("GET", "h", "/x", ""), Tier::High)
        .await
        .expect("hit");
    assert_eq!(entry.max_age, 30);
}

// --- Auth gate ---------------------------------------------------------------

#[tokio::test]
async fn auth_bypass_takes_precedence_over_matching_route() {
    // Even with a matching public route, Authorization → bypass.
    let c = cache_with(vec![rule_doc("static", "/static/", 1800, vec!["asset".into()])]);
    let stored = put(
        &c,
        "GET",
        "h",
        "/static/x.js",
        "",
        None,
        Tier::Medium,
        &POLICY_AGGRESSIVE_300,
        true, // has_authorization
        false,
    )
    .await;
    assert!(!stored);
    assert_eq!(c.stats().bypassed_authenticated, 1);
}

// --- Tier-gate symmetry (FR-009 AC-1) ---------------------------------------

// FR-009 AC-1: a CRITICAL `get()` must miss even on entries inserted under a
// less-strict tier. Guard against tier reclassification mid-flight.
#[tokio::test]
async fn critical_get_misses_entry_inserted_under_medium() {
    let c = cache_with(vec![]);
    assert!(
        put(
            &c,
            "GET",
            "h",
            "/x",
            "",
            Some("max-age=600"),
            Tier::Medium,
            &POLICY_AGGRESSIVE_300,
            false,
            false,
        )
        .await
    );
    let r = c
        .get(&ResponseCache::make_key("GET", "h", "/x", ""), Tier::Critical)
        .await;
    assert!(r.is_none());
    assert!(c.stats().bypassed_critical >= 1);
}

// --- Tag index gauge ---------------------------------------------------------

#[tokio::test]
async fn tag_index_shrinks_after_purge() {
    let c = cache_with(vec![rule_doc("static", "/p", 600, vec!["asset".into()])]);
    for i in 0..50u32 {
        let key = format!("/p/{i}");
        assert!(
            put(
                &c,
                "GET",
                "h",
                &key,
                "",
                None,
                Tier::Medium,
                &POLICY_AGGRESSIVE_300,
                false,
                false,
            )
            .await
        );
    }
    assert_eq!(c.tag_index_size(), 50);
    let purged = c.purge_by_tag("asset").await;
    assert_eq!(purged, 50);
    assert_eq!(c.tag_index_size(), 0);
}
