//! In-memory LRU response cache backed by `moka`.
//!
//! Cache key = `method:host:path?query`
//! Respects Cache-Control directives: `no-cache`, `no-store`, `private`, `max-age=N`.
//!
//! Tier-gated (FR-009 AC-1): CRITICAL-tier responses are NEVER cached, even if
//! upstream sends `Cache-Control: max-age=N`. The per-tier `CachePolicy` also
//! caps and/or defaults TTL — upstream cannot exceed the policy ceiling.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use moka::future::Cache;
use tracing::{debug, trace};
use waf_common::tier::{CachePolicy, Tier};

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

/// Cache statistics counters
#[derive(Debug, Default)]
pub struct CacheStats {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub evictions: AtomicU64,
    pub stores: AtomicU64,
    /// Count of put/get calls bypassed by tier or `NoCache` policy.
    /// Audit signal for FR-009 AC-1: must increment on every CRITICAL touch.
    pub bypassed_critical: AtomicU64,
}

impl CacheStats {
    pub fn snapshot(&self) -> CacheStatsSnapshot {
        CacheStatsSnapshot {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            stores: self.stores.load(Ordering::Relaxed),
            bypassed_critical: self.bypassed_critical.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CacheStatsSnapshot {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub stores: u64,
    pub bypassed_critical: u64,
}

/// Shared response cache
pub struct ResponseCache {
    inner: Cache<String, Arc<CachedResponse>>,
    stats: Arc<CacheStats>,
    default_ttl: Duration,
    max_ttl: Duration,
}

impl ResponseCache {
    /// Create a new cache.
    ///
    /// `max_size_mb`: maximum total size in MiB (approximate, measured by entry count).
    pub fn new(max_size_mb: u64, default_ttl_secs: u64, max_ttl_secs: u64) -> Arc<Self> {
        // Use entry count as capacity (each ~1 MiB avg → × 1024 entries per MB)
        let capacity = (max_size_mb * 16).max(64);
        let stats = Arc::new(CacheStats::default());

        let inner = Cache::builder()
            .max_capacity(capacity)
            .time_to_live(Duration::from_secs(max_ttl_secs))
            .build();

        Arc::new(Self {
            inner,
            stats,
            default_ttl: Duration::from_secs(default_ttl_secs),
            max_ttl: Duration::from_secs(max_ttl_secs),
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

    /// Store a response, honouring tier policy and Cache-Control directives.
    ///
    /// Returns `false` if the response must not be cached. Bypass order:
    /// 1. CRITICAL tier or `CachePolicy::NoCache` — non-overridable
    /// 2. Any `Set-Cookie` header — per-user response, never shared
    /// 3. Non-2xx status
    /// 4. Upstream `Cache-Control` says no-store / no-cache / private
    ///
    /// Otherwise TTL = upstream `max-age` capped by the per-tier policy
    /// ceiling, or the policy default if upstream is silent.
    pub async fn put(
        &self,
        key: String,
        status: u16,
        headers: Vec<(String, String)>,
        body: Bytes,
        cache_control: Option<&str>,
        tier: Tier,
        policy: &CachePolicy,
    ) -> bool {
        // Gate 1: CRITICAL + NoCache are non-overridable (audit invariant).
        if matches!(tier, Tier::Critical) || matches!(policy, CachePolicy::NoCache) {
            self.stats.bypassed_critical.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // Gate 2: Set-Cookie responses are per-user; never share across requests.
        if headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
        {
            debug!(key = %key, "skipping cache: Set-Cookie present");
            return false;
        }

        // Only cache 2xx responses on GET/HEAD
        if !(200..300).contains(&status) {
            return false;
        }

        let ttl = match parse_cache_control(cache_control) {
            CacheDecision::NoStore | CacheDecision::NoCache | CacheDecision::Private => {
                debug!(key = %key, "skipping cache: Cache-Control directive");
                return false;
            }
            CacheDecision::MaxAge(secs) => apply_policy_cap(secs, policy, self.max_ttl.as_secs()),
            CacheDecision::Default => apply_policy_default(policy, self.default_ttl.as_secs()),
        };

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

    /// Invalidate all entries for a given host.
    pub async fn purge_host(&self, host: &str) {
        // moka doesn't support prefix-based invalidation; collect keys first
        let keys: Vec<String> = self
            .inner
            .iter()
            .filter(|(k, _)| {
                // key format: method:host:path...
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

// ─── Cache-Control parser ─────────────────────────────────────────────────────

enum CacheDecision {
    Default,
    NoStore,
    NoCache,
    Private,
    MaxAge(u64),
}

/// Cap an upstream-supplied `max-age` by the tier policy ceiling, then by the
/// global `max_ttl`. Variants without a ceiling fall back to `hard_max`.
fn apply_policy_cap(upstream_secs: u64, policy: &CachePolicy, hard_max: u64) -> Duration {
    let policy_ceiling = match policy {
        CachePolicy::NoCache => 0, // already bypassed; defensive zero
        CachePolicy::ShortTtl { ttl_seconds } | CachePolicy::Aggressive { ttl_seconds } => {
            u64::from(*ttl_seconds)
        }
        CachePolicy::Default { .. } => hard_max,
    };
    Duration::from_secs(upstream_secs.min(policy_ceiling).min(hard_max))
}

/// Choose a TTL when upstream did not specify Cache-Control. Uses the policy's
/// configured TTL; falls back to the cache's `default_ttl` only for variants
/// without a TTL (i.e. `NoCache`, which is already bypassed upstream).
fn apply_policy_default(policy: &CachePolicy, fallback_secs: u64) -> Duration {
    let secs = match policy {
        CachePolicy::NoCache => fallback_secs, // unreachable in practice
        CachePolicy::ShortTtl { ttl_seconds }
        | CachePolicy::Aggressive { ttl_seconds }
        | CachePolicy::Default { ttl_seconds } => u64::from(*ttl_seconds),
    };
    Duration::from_secs(secs)
}

fn parse_cache_control(header: Option<&str>) -> CacheDecision {
    let Some(header) = header else {
        return CacheDecision::Default;
    };
    let lower = header.to_lowercase();
    if lower.contains("no-store") {
        return CacheDecision::NoStore;
    }
    if lower.contains("no-cache") {
        return CacheDecision::NoCache;
    }
    if lower.contains("private") {
        return CacheDecision::Private;
    }
    for part in lower.split(',') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("max-age=")
            && let Ok(secs) = rest.trim().parse::<u64>()
        {
            return CacheDecision::MaxAge(secs);
        }
    }
    CacheDecision::Default
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

    #[tokio::test]
    async fn critical_tier_bypasses_put_even_with_max_age() {
        let c = cache();
        let stored = c
            .put(
                key(),
                200,
                vec![],
                Bytes::from("ok"),
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
        // Insert as Medium first.
        let stored = c
            .put(
                key(),
                200,
                vec![],
                Bytes::from("ok"),
                Some("max-age=60"),
                Tier::Medium,
                &CachePolicy::Aggressive { ttl_seconds: 300 },
            )
            .await;
        assert!(stored);
        // Reclassified to Critical mid-stream → must not serve.
        let r = c.get(&key(), Tier::Critical).await;
        assert!(r.is_none());
        assert!(c.stats().bypassed_critical >= 1);
    }

    #[tokio::test]
    async fn no_cache_policy_bypasses_regardless_of_tier() {
        let c = cache();
        let stored = c
            .put(
                key(),
                200,
                vec![],
                Bytes::from("ok"),
                Some("max-age=600"),
                Tier::Medium,
                &CachePolicy::NoCache,
            )
            .await;
        assert!(!stored);
        assert_eq!(c.stats().bypassed_critical, 1);
    }

    #[tokio::test]
    async fn aggressive_caps_upstream_max_age_above_ceiling() {
        let c = cache();
        c.put(
            key(),
            200,
            vec![],
            Bytes::from("ok"),
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
        c.put(
            key(),
            200,
            vec![],
            Bytes::from("ok"),
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
        c.put(
            key(),
            200,
            vec![],
            Bytes::from("ok"),
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
        let stored = c
            .put(
                key(),
                200,
                vec![("Set-Cookie".into(), "sid=abc".into())],
                Bytes::from("ok"),
                Some("max-age=600"),
                Tier::Medium,
                &CachePolicy::Aggressive { ttl_seconds: 300 },
            )
            .await;
        assert!(!stored);
        // Set-Cookie bypass is auth-flow protection, not a CRITICAL bypass.
        assert_eq!(c.stats().bypassed_critical, 0);
    }
}
