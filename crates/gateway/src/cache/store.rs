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
use moka::notification::RemovalCause;
use tracing::{debug, trace};
use waf_common::tier::{CachePolicy, Tier};

use super::gates::{AuthGate, MethodGate, RouteRuleGate, TierDefaultGate, TierGate, UpstreamCcGate};
use super::policy::{CacheCtx, CachePolicyResolver, Verdict};
use super::rule_set::{CompiledRuleSet, RuleSetHolder};
use super::stats::{CacheStats, CacheStatsSnapshot};
use super::tag_index::TagIndex;

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
    /// FR-009 Phase 4: reverse index for tag-based purge.
    tag_index: Arc<TagIndex>,
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
        let tag_index = Arc::new(TagIndex::new());

        // FR-009 Phase 4: keep tag index in sync with moka. Without this hook
        // a TTL-expired or LRU-evicted entry leaks its key in the index until
        // the next purge sweep. The closure is sync (moka invokes it from a
        // maintenance task); only an in-memory DashMap update happens here so
        // there is no need for `async_eviction_listener`.
        //
        // `Replaced` is filtered out: when `put` overwrites an existing key,
        // moka schedules eviction-listener for the *old* value, but that task
        // can run AFTER `put` has already re-registered the new tags. Acting
        // on `Replaced` would then wipe the fresh index entry and orphan the
        // new value (`purge_by_tag` would miss it until TTL). The `put` path
        // always re-registers, so `Replaced` cleanup is both redundant and
        // racy.
        let tag_index_for_evict = Arc::clone(&tag_index);
        let inner = Cache::builder()
            .max_capacity(capacity)
            .time_to_live(Duration::from_secs(max_ttl_secs))
            .eviction_listener(move |k: Arc<String>, _v: Arc<CachedResponse>, cause: RemovalCause| {
                if matches!(cause, RemovalCause::Replaced) {
                    return;
                }
                tag_index_for_evict.unregister(&Arc::<str>::from(k.as_str()));
            })
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
            tag_index,
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
            Verdict::Cache { ttl, tags } => {
                let entry = Arc::new(CachedResponse {
                    status,
                    headers,
                    body,
                    max_age: ttl.as_secs(),
                });
                let key_for_index: Option<Arc<str>> = if tags.is_empty() {
                    None
                } else {
                    Some(Arc::<str>::from(key.as_str()))
                };
                self.inner.insert(key, entry).await;
                if let Some(k) = key_for_index {
                    self.tag_index.register(&k, &tags);
                }
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
        // Eviction listener will fire for each entry, but `invalidate_all`
        // is async-batched — clear the index synchronously too so callers
        // observe a zero gauge immediately after `flush().await` returns.
        self.tag_index.clear();
    }

    /// FR-009 Phase 4: purge every entry tagged with `tag`. Returns the count.
    /// Snapshot-then-remove avoids holding `DashMap` shard locks across `await`.
    pub async fn purge_by_tag(&self, tag: &str) -> usize {
        let keys = self.tag_index.keys_for_tag(tag);
        let n = self.purge_keys(keys).await;
        self.stats.purges_tag.fetch_add(n as u64, Ordering::Relaxed);
        n
    }

    /// FR-009 Phase 4: purge every entry cached by the rule with this `id`.
    /// Implemented as a tag lookup because `RouteRuleGate` auto-prepends the
    /// rule id to every entry's tag list.
    pub async fn purge_by_route_id(&self, route_id: &str) -> usize {
        let keys = self.tag_index.keys_for_tag(route_id);
        let n = self.purge_keys(keys).await;
        self.stats.purges_route.fetch_add(n as u64, Ordering::Relaxed);
        n
    }

    /// Internal: remove the given keys from moka and the tag index.
    async fn purge_keys(&self, keys: Vec<Arc<str>>) -> usize {
        let count = keys.len();
        for k in keys {
            self.inner.remove(k.as_ref()).await;
            // Eviction listener will also call `unregister`; calling it here
            // is idempotent and ensures the index is consistent the moment
            // this method returns (eviction listener runs out-of-band).
            self.tag_index.unregister(&k);
        }
        count
    }

    /// FR-009 Phase 4: number of distinct keys currently tracked by the tag
    /// index (gauge, not a counter).
    pub fn tag_index_size(&self) -> usize {
        self.tag_index.key_count()
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

    // FR-009 Phase 4 tests --------------------------------------------------

    /// Build a single-rule cache and return both the cache and the rule's
    /// declared tag for symmetry with the assertions.
    fn cache_with_rule(rule_id: &str, prefix: &str, ttl_secs: u32, tags: Vec<String>) -> Arc<ResponseCache> {
        use crate::cache::config::{CacheConfigDoc, Defaults, MatchDoc, PathSpec, RuleDoc};
        let doc = CacheConfigDoc {
            version: 1,
            defaults: Defaults::default(),
            rules: vec![RuleDoc {
                id: rule_id.into(),
                match_: MatchDoc {
                    host: None,
                    path: PathSpec::Prefix { prefix: prefix.into() },
                    methods: None,
                },
                ttl_seconds: ttl_secs,
                tags,
                allow_authenticated: false,
            }],
        };
        let set = CompiledRuleSet::try_from_doc(doc).unwrap();
        ResponseCache::with_rules(8, 60, 3600, RuleSetHolder::new(set))
    }

    async fn put_under_rule(c: &ResponseCache, key: &str, host: &str, path: &str) -> bool {
        c.put(
            key.to_string(),
            host,
            path,
            200,
            vec![],
            Bytes::from("ok"),
            None,
            Tier::Medium,
            &CachePolicy::Aggressive { ttl_seconds: 300 },
            false,
            false,
        )
        .await
    }

    #[tokio::test]
    async fn purge_by_tag_removes_only_matching_entries() {
        let c = cache_with_rule("static", "/p", 600, vec!["catalog".into()]);
        assert!(put_under_rule(&c, "GET:h:/p/a", "h", "/p/a").await);
        assert!(put_under_rule(&c, "GET:h:/p/b", "h", "/p/b").await);
        assert_eq!(c.tag_index_size(), 2);

        let purged = c.purge_by_tag("catalog").await;
        assert_eq!(purged, 2);
        assert_eq!(c.tag_index_size(), 0);
        assert!(c.get("GET:h:/p/a", Tier::Medium).await.is_none());
        assert!(c.get("GET:h:/p/b", Tier::Medium).await.is_none());
        assert_eq!(c.stats().purges_tag, 2);
    }

    #[tokio::test]
    async fn purge_by_unknown_tag_returns_zero() {
        let c = cache_with_rule("static", "/p", 600, vec!["catalog".into()]);
        assert!(put_under_rule(&c, "GET:h:/p/a", "h", "/p/a").await);
        let purged = c.purge_by_tag("nonexistent").await;
        assert_eq!(purged, 0);
        // Untouched entry must still be present.
        assert!(c.get("GET:h:/p/a", Tier::Medium).await.is_some());
    }

    #[tokio::test]
    async fn purge_by_route_id_uses_auto_prepended_tag() {
        // Operator only declared `catalog`, but route_id `static` was
        // auto-prepended by RouteRuleGate so this must still work.
        let c = cache_with_rule("static", "/p", 600, vec!["catalog".into()]);
        assert!(put_under_rule(&c, "GET:h:/p/a", "h", "/p/a").await);
        let purged = c.purge_by_route_id("static").await;
        assert_eq!(purged, 1);
        assert_eq!(c.stats().purges_route, 1);
        assert_eq!(
            c.stats().purges_tag,
            0,
            "route purge must not double-count as tag purge"
        );
    }

    #[tokio::test]
    async fn flush_clears_tag_index() {
        let c = cache_with_rule("static", "/p", 600, vec!["catalog".into()]);
        assert!(put_under_rule(&c, "GET:h:/p/a", "h", "/p/a").await);
        assert!(c.tag_index_size() >= 1);
        c.flush().await;
        assert_eq!(c.tag_index_size(), 0);
    }

    #[tokio::test]
    async fn untagged_entries_do_not_grow_tag_index() {
        // Plain cache (no rules) → UpstreamCcGate / TierDefaultGate produce
        // empty tag lists; the index must stay empty.
        let c = cache();
        assert!(
            put_basic(
                &c,
                vec![],
                Some("max-age=600"),
                Tier::Medium,
                &CachePolicy::Aggressive { ttl_seconds: 300 },
            )
            .await
        );
        assert_eq!(c.tag_index_size(), 0);
    }

    #[tokio::test]
    async fn concurrent_put_and_purge_no_deadlock() {
        let c = cache_with_rule("static", "/p", 600, vec!["catalog".into()]);
        // Pre-seed so `purge_by_tag` has something to chew on while puts race.
        for i in 0..32 {
            assert!(
                put_under_rule(&c, &format!("GET:h:/p/{i}"), "h", &format!("/p/{i}")).await,
                "seed put {i}"
            );
        }

        let c1 = Arc::clone(&c);
        let c2 = Arc::clone(&c);
        let writer = tokio::spawn(async move {
            for i in 32..96 {
                let _ = put_under_rule(&c1, &format!("GET:h:/p/{i}"), "h", &format!("/p/{i}")).await;
            }
        });
        let purger = tokio::spawn(async move {
            for _ in 0..4 {
                let _ = c2.purge_by_tag("catalog").await;
                tokio::task::yield_now().await;
            }
        });
        let (w, p) = tokio::join!(writer, purger);
        w.expect("writer task");
        p.expect("purger task");
        // Final purge — index must be reachable and consistent.
        let _ = c.purge_by_tag("catalog").await;
        assert_eq!(c.tag_index_size(), 0, "index must drain after final purge");
    }

    // Coverage for purge_host / purge_key / entry_count (FR-009 phase-05).
    #[tokio::test]
    async fn purge_host_removes_only_matching_host_entries() {
        let c = cache();
        for (host, path) in [("a", "/x"), ("a", "/y"), ("b", "/z")] {
            c.put(
                ResponseCache::make_key("GET", host, path, ""),
                host,
                path,
                200,
                vec![],
                Bytes::from("ok"),
                Some("max-age=60"),
                Tier::Medium,
                &CachePolicy::Aggressive { ttl_seconds: 300 },
                false,
                false,
            )
            .await;
        }
        c.inner.run_pending_tasks().await;
        assert_eq!(c.entry_count(), 3);
        c.purge_host("a").await;
        c.inner.run_pending_tasks().await;
        // Only host=a entries gone; host=b survives.
        assert!(c.get("GET:a:/x", Tier::Medium).await.is_none());
        assert!(c.get("GET:a:/y", Tier::Medium).await.is_none());
        assert!(c.get("GET:b:/z", Tier::Medium).await.is_some());
    }

    #[tokio::test]
    async fn purge_key_removes_single_entry() {
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
        assert!(c.get(&key(), Tier::Medium).await.is_some());
        c.purge_key(&key()).await;
        assert!(c.get(&key(), Tier::Medium).await.is_none());
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
