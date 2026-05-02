//! In-memory LRU response cache backed by `moka`.
//!
//! Cache key = `method:host:path?query`
//!
//! `put` delegates to `CachePolicyResolver` (Chain of Responsibility); `get`
//! keeps the inline CRITICAL-tier check (cheap, hot path, single concern).
//!
//! Tier-gated (FR-009 AC-1): CRITICAL-tier responses are NEVER cached. The
//! per-tier `CachePolicy` also caps TTL — upstream cannot exceed the ceiling.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use moka::future::Cache;
use tracing::{debug, trace};
use waf_common::tier::{CachePolicy, Tier};

use super::gates::{AuthGate, MethodGate, RouteRuleGate, TierDefaultGate, TierGate, UpstreamCcGate};
use super::policy::{CacheCtx, CachePolicyResolver, Verdict};
use super::rule_set::{CompiledRuleSet, RuleSetHolder};
use super::stats::{CacheStats, CacheStatsSnapshot};

/// A cached HTTP response
#[derive(Debug, Clone)]
pub struct CachedResponse {
    pub status: u16,
    /// Response headers as (name, value) pairs
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
    /// Seconds until expiry (from insertion time)
    pub max_age: u64,
}

/// Shared response cache
pub struct ResponseCache {
    inner: Cache<String, Arc<CachedResponse>>,
    stats: Arc<CacheStats>,
    default_ttl: Duration,
    max_ttl: Duration,
    resolver: CachePolicyResolver,
}

impl ResponseCache {
    /// Create a new cache.
    ///
    /// `max_size_mb`: maximum total size in MiB (approximate, measured by entry count).
    pub fn new(max_size_mb: u64, default_ttl_secs: u64, max_ttl_secs: u64) -> Arc<Self> {
        Self::with_rules(
            max_size_mb,
            default_ttl_secs,
            max_ttl_secs,
            RuleSetHolder::new(CompiledRuleSet::empty()),
        )
    }

    /// Build a cache with a hot-swappable rule set. The caller owns the
    /// `RuleSetHolder` (and any `CacheRuleWatcher` wired to it). FR-009 Phase 3.
    ///
    /// Resolver order (locked):
    /// `TierGate → MethodGate → AuthGate → RouteRule → UpstreamCcGate → TierDefaultGate`.
    pub fn with_rules(
        max_size_mb: u64,
        default_ttl_secs: u64,
        max_ttl_secs: u64,
        rules: Arc<RuleSetHolder>,
    ) -> Arc<Self> {
        let capacity = (max_size_mb * 16).max(64);
        let stats = Arc::new(CacheStats::default());

        let inner = Cache::builder()
            .max_capacity(capacity)
            .time_to_live(Duration::from_secs(max_ttl_secs))
            .build();

        let resolver = CachePolicyResolver::new(vec![
            Box::new(TierGate),
            Box::new(MethodGate),
            Box::new(AuthGate),
            Box::new(RouteRuleGate::new(rules)),
            Box::new(UpstreamCcGate),
            Box::new(TierDefaultGate),
        ]);

        Arc::new(Self {
            inner,
            stats,
            default_ttl: Duration::from_secs(default_ttl_secs),
            max_ttl: Duration::from_secs(max_ttl_secs),
            resolver,
        })
    }

    /// Build the cache key for a request.
    pub fn make_key(method: &str, host: &str, path: &str, query: &str) -> String {
        if query.is_empty() {
            format!("{method}:{host}:{path}")
        } else {
            format!("{method}:{host}:{path}?{query}")
        }
    }

    /// Look up a cached response. Returns `None` on miss or on tier bypass.
    ///
    /// Symmetric tier gate (FR-009 AC-1): if the request's tier is CRITICAL,
    /// never serve a cached entry — even one inserted before reclassification.
    pub async fn get(&self, key: &str, tier: Tier) -> Option<Arc<CachedResponse>> {
        if matches!(tier, Tier::Critical) {
            self.stats.bypassed_critical.fetch_add(1, Ordering::Relaxed);
            trace!(key = %key, "cache bypass: CRITICAL tier");
            return None;
        }
        let result = self.inner.get(key).await;
        if result.is_some() {
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
            trace!(key = %key, "cache hit");
        } else {
            self.stats.misses.fetch_add(1, Ordering::Relaxed);
            trace!(key = %key, "cache miss");
        }
        result
    }

    /// Store a response. Decision is delegated to `CachePolicyResolver`.
    /// Returns `false` if any gate bypassed.
    ///
    /// `host`/`path` and `has_authorization`/`has_cookie` feed the FR-009
    /// Phase 3 gates (`RouteRuleGate`, `AuthGate`). Callers probe the request
    /// once and pass the result; gates do not re-parse headers.
    #[allow(clippy::too_many_arguments)]
    pub async fn put(
        &self,
        key: String,
        host: &str,
        path: &str,
        status: u16,
        headers: Vec<(String, String)>,
        body: Bytes,
        cache_control: Option<&str>,
        tier: Tier,
        policy: &CachePolicy,
        has_authorization: bool,
        has_cookie: bool,
    ) -> bool {
        // Method extracted from key prefix (`method:host:path[?query]`).
        let method = key.split(':').next().unwrap_or("");
        let ctx = CacheCtx {
            tier,
            method,
            host,
            path,
            status,
            headers: &headers,
            cache_control,
            policy,
            max_ttl_secs: self.max_ttl.as_secs(),
            default_ttl_secs: self.default_ttl.as_secs(),
            has_authorization,
            has_cookie,
        };

        match self.resolver.resolve(&ctx) {
            Verdict::Bypass(reason) => {
                self.stats.record_bypass(reason);
                debug!(key = %key, ?reason, "cache bypass");
                false
            }
            Verdict::Cache { ttl, tags: _ } => {
                let entry = Arc::new(CachedResponse {
                    status,
                    headers,
                    body,
                    max_age: ttl.as_secs(),
                });
                self.inner.insert(key, entry).await;
                self.stats.stores.fetch_add(1, Ordering::Relaxed);
                true
            }
            // Resolver always terminates with Bypass(NoMatch); defensive arm.
            Verdict::Continue => false,
        }
    }

    /// Invalidate all entries for a given host.
    pub async fn purge_host(&self, host: &str) {
        let keys: Vec<String> = self
            .inner
            .iter()
            .filter(|(k, _)| {
                let parts: Vec<&str> = k.splitn(3, ':').collect();
                parts.get(1).copied() == Some(host)
            })
            .map(|(k, _)| k.to_string())
            .collect();
        for k in keys {
            self.inner.remove(&k).await;
        }
    }

    /// Invalidate a single cache key.
    pub async fn purge_key(&self, key: &str) {
        self.inner.remove(key).await;
    }

    /// Flush the entire cache.
    pub async fn flush(&self) {
        self.inner.invalidate_all();
        self.inner.run_pending_tasks().await;
    }

    /// Return current statistics.
    pub fn stats(&self) -> CacheStatsSnapshot {
        self.stats.snapshot()
    }

    /// Approximate entry count.
    pub fn entry_count(&self) -> u64 {
        self.inner.entry_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache() -> Arc<ResponseCache> {
        ResponseCache::new(8, 60, 3600)
    }

    fn key() -> String {
        "GET:h:/p".to_string()
    }

    /// Test helper — wraps the now-extended `put()` signature so individual
    /// tests stay readable. Anonymous + no Set-Cookie unless overridden.
    async fn put_basic(
        c: &ResponseCache,
        headers: Vec<(String, String)>,
        cc: Option<&str>,
        tier: Tier,
        policy: &CachePolicy,
    ) -> bool {
        c.put(
            key(),
            "h",
            "/p",
            200,
            headers,
            Bytes::from("ok"),
            cc,
            tier,
            policy,
            false,
            false,
        )
        .await
    }

    #[tokio::test]
    async fn critical_tier_bypasses_put_even_with_max_age() {
        let c = cache();
        let stored = put_basic(
            &c,
            vec![],
            Some("max-age=3600"),
            Tier::Critical,
            &CachePolicy::Aggressive { ttl_seconds: 300 },
        )
        .await;
        assert!(!stored, "CRITICAL must never cache");
        assert_eq!(c.stats().bypassed_critical, 1);
        assert_eq!(c.stats().stores, 0);
    }

    #[tokio::test]
    async fn critical_tier_bypasses_get_even_for_existing_key() {
        let c = cache();
        let stored = put_basic(
            &c,
            vec![],
            Some("max-age=60"),
            Tier::Medium,
            &CachePolicy::Aggressive { ttl_seconds: 300 },
        )
        .await;
        assert!(stored);
        let r = c.get(&key(), Tier::Critical).await;
        assert!(r.is_none());
        assert!(c.stats().bypassed_critical >= 1);
    }

    #[tokio::test]
    async fn no_cache_policy_bypasses_regardless_of_tier() {
        let c = cache();
        let stored = put_basic(&c, vec![], Some("max-age=600"), Tier::Medium, &CachePolicy::NoCache).await;
        assert!(!stored);
        assert_eq!(c.stats().bypassed_critical, 1);
    }

    #[tokio::test]
    async fn aggressive_caps_upstream_max_age_above_ceiling() {
        let c = cache();
        put_basic(
            &c,
            vec![],
            Some("max-age=10000"),
            Tier::Medium,
            &CachePolicy::Aggressive { ttl_seconds: 300 },
        )
        .await;
        let entry = c.get(&key(), Tier::Medium).await.expect("present");
        assert_eq!(entry.max_age, 300, "must cap to policy ceiling");
    }

    #[tokio::test]
    async fn aggressive_uses_policy_default_when_upstream_silent() {
        let c = cache();
        put_basic(
            &c,
            vec![],
            None,
            Tier::Medium,
            &CachePolicy::Aggressive { ttl_seconds: 300 },
        )
        .await;
        let entry = c.get(&key(), Tier::Medium).await.expect("present");
        assert_eq!(entry.max_age, 300);
    }

    #[tokio::test]
    async fn short_ttl_caps_upstream_below_ceiling_unchanged() {
        let c = cache();
        put_basic(
            &c,
            vec![],
            Some("max-age=30"),
            Tier::Medium,
            &CachePolicy::ShortTtl { ttl_seconds: 120 },
        )
        .await;
        let entry = c.get(&key(), Tier::Medium).await.expect("present");
        assert_eq!(entry.max_age, 30, "below ceiling stays as-is");
    }

    #[tokio::test]
    async fn set_cookie_response_bypasses_cache() {
        let c = cache();
        let stored = put_basic(
            &c,
            vec![("Set-Cookie".into(), "sid=abc".into())],
            Some("max-age=600"),
            Tier::Medium,
            &CachePolicy::Aggressive { ttl_seconds: 300 },
        )
        .await;
        assert!(!stored);
        assert_eq!(c.stats().bypassed_critical, 0);
    }

    // FR-009 Phase 3 tests ---------------------------------------------------

    #[tokio::test]
    async fn auth_request_bypasses_via_authorization_header() {
        let c = cache();
        let stored = c
            .put(
                key(),
                "h",
                "/p",
                200,
                vec![],
                Bytes::from("ok"),
                Some("max-age=600"),
                Tier::Medium,
                &CachePolicy::Aggressive { ttl_seconds: 300 },
                true,  // has_authorization
                false, // has_cookie
            )
            .await;
        assert!(!stored);
        assert_eq!(c.stats().bypassed_authenticated, 1);
        assert_eq!(c.stats().bypassed_critical, 0);
    }

    #[tokio::test]
    async fn auth_request_bypasses_via_cookie_header() {
        let c = cache();
        let stored = c
            .put(
                key(),
                "h",
                "/p",
                200,
                vec![],
                Bytes::from("ok"),
                Some("max-age=600"),
                Tier::Medium,
                &CachePolicy::Aggressive { ttl_seconds: 300 },
                false,
                true,
            )
            .await;
        assert!(!stored);
        assert_eq!(c.stats().bypassed_authenticated, 1);
    }

    #[tokio::test]
    async fn route_rule_ttl_overrides_upstream_when_anonymous() {
        use crate::cache::config::{CacheConfigDoc, Defaults, MatchDoc, PathSpec, RuleDoc};
        let doc = CacheConfigDoc {
            version: 1,
            defaults: Defaults::default(),
            rules: vec![RuleDoc {
                id: "static".into(),
                match_: MatchDoc {
                    host: None,
                    path: PathSpec::Prefix { prefix: "/p".into() },
                    methods: None,
                },
                ttl_seconds: 1800,
                tags: vec!["static".into()],
                allow_authenticated: false,
            }],
        };
        let set = CompiledRuleSet::try_from_doc(doc).unwrap();
        let holder = RuleSetHolder::new(set);
        let c = ResponseCache::with_rules(8, 60, 3600, holder);

        let stored = c
            .put(
                key(),
                "h",
                "/p",
                200,
                vec![],
                Bytes::from("ok"),
                None, // no upstream Cache-Control → route rule wins
                Tier::Medium,
                &CachePolicy::Aggressive { ttl_seconds: 300 },
                false,
                false,
            )
            .await;
        assert!(stored);
        let entry = c.get(&key(), Tier::Medium).await.expect("present");
        assert_eq!(entry.max_age, 1800, "route rule TTL must apply");
    }
}
