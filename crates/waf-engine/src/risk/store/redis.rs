//! FR-025 Phase 7: Redis-backed `RiskStore` for cluster-wide risk state.
//!
//! Key layout:
//! - `waf:risk:state:{owner_id}` → JSON-encoded `RiskState` (TTL: `ttl_secs`)
//! - `waf:risk:idx:ip:{ip}` → `owner_id`
//! - `waf:risk:idx:fp:{fp_hash}` → `owner_id`
//! - `waf:risk:idx:sid:{session_hex}` → `owner_id`
//!
//! `owner_id` is a UUID minted on first apply for a new actor. Triple-key
//! indices converge to a single owner on collision (max-score wins).
//!
//! # Decay Behavior
//!
//! The Redis store applies decay atomically within the Lua `apply` script,
//! before folding new deltas. This differs from the memory store where decay
//! is a separate call in the pipeline. Both produce equivalent results but
//! the Redis store cannot support "apply without decay" as a separate operation.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use parking_lot::Mutex;
use redis::{Script, aio::ConnectionManager};
use tokio::time::timeout;
use tracing::{debug, warn};

use super::redis_lua::{APPLY_SCRIPT, FORCE_MAX_SCRIPT, MINT_OR_GET_OWNER_SCRIPT};
use crate::risk::decay::{DECAY_RATE, MAX_DECAY, MIN_CLEAN_STREAK};
use crate::risk::key::RiskKey;
use crate::risk::state::{Contributor, RiskState};
use crate::risk::store::store_trait::{ApplyResult, RiskStore};

/// Configuration for the Redis risk store backend.
#[derive(Clone, Debug)]
pub struct RedisRiskConfig {
    /// Redis URL, e.g. `redis://127.0.0.1:6379`.
    pub url: String,
    /// Key prefix for namespacing (default: `waf:risk:`).
    pub key_prefix: String,
    /// TTL for state entries in seconds (default: 1800 = 30 min).
    pub ttl_secs: u32,
    /// Per-operation timeout (default: 100ms).
    pub op_timeout: Duration,
    /// Consecutive failures before circuit breaker opens (default: 5).
    pub breaker_threshold: u32,
    /// LRU cache capacity for fail-open fallback (default: 10000).
    pub cache_capacity: usize,
}

impl Default for RedisRiskConfig {
    fn default() -> Self {
        Self {
            url: "redis://127.0.0.1:6379".into(),
            key_prefix: "waf:risk:".into(),
            ttl_secs: 1800,
            op_timeout: Duration::from_millis(100),
            breaker_threshold: 5,
            cache_capacity: 10_000,
        }
    }
}

/// Fail-open LRU cache entry.
struct CacheEntry {
    state: RiskState,
    #[allow(dead_code)] // Stored for cache invalidation by owner_id if needed
    owner_id: String,
}

/// Simple LRU cache for fail-open fallback.
struct LruCache {
    entries: std::collections::HashMap<String, CacheEntry>,
    order: std::collections::VecDeque<String>,
    capacity: usize,
}

impl LruCache {
    fn new(capacity: usize) -> Self {
        Self {
            entries: std::collections::HashMap::with_capacity(capacity),
            order: std::collections::VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    fn get(&mut self, key: &str) -> Option<&CacheEntry> {
        if self.entries.contains_key(key) {
            self.order.retain(|k| k != key);
            self.order.push_back(key.to_string());
            self.entries.get(key)
        } else {
            None
        }
    }

    fn insert(&mut self, key: String, entry: CacheEntry) {
        if self.entries.len() >= self.capacity
            && let Some(oldest) = self.order.pop_front()
        {
            self.entries.remove(&oldest);
        }
        self.order.retain(|k| k != &key);
        self.order.push_back(key.clone());
        self.entries.insert(key, entry);
    }
}

/// Redis-backed risk store with circuit breaker and LRU fallback cache.
pub struct RedisRiskStore {
    conn: ConnectionManager,
    cfg: RedisRiskConfig,
    consecutive_fails: AtomicU32,
    cache: Mutex<LruCache>,
    apply_script: Script,
    force_max_script: Script,
    mint_owner_script: Script,
}

impl std::fmt::Debug for RedisRiskStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisRiskStore")
            .field("cfg", &self.cfg)
            .field("consecutive_fails", &self.consecutive_fails.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl RedisRiskStore {
    /// Create a new Redis risk store, verifying connectivity with PING.
    ///
    /// # Errors
    /// Returns error if connection fails or PING times out.
    pub async fn new(cfg: RedisRiskConfig) -> anyhow::Result<Self> {
        let client =
            redis::Client::open(cfg.url.as_str()).with_context(|| format!("risk redis: open client {}", cfg.url))?;
        let mut conn = ConnectionManager::new(client)
            .await
            .context("risk redis: connection manager init")?;
        let _: String = redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .context("risk redis: ping")?;

        Ok(Self {
            conn,
            cache: Mutex::new(LruCache::new(cfg.cache_capacity)),
            consecutive_fails: AtomicU32::new(0),
            apply_script: Script::new(APPLY_SCRIPT),
            force_max_script: Script::new(FORCE_MAX_SCRIPT),
            mint_owner_script: Script::new(MINT_OR_GET_OWNER_SCRIPT),
            cfg,
        })
    }

    /// True once `breaker_threshold` consecutive failures have occurred.
    #[must_use]
    pub fn breaker_open(&self) -> bool {
        self.consecutive_fails.load(Ordering::Relaxed) >= self.cfg.breaker_threshold
    }

    fn record_ok(&self) {
        self.consecutive_fails.store(0, Ordering::Relaxed);
    }

    fn record_fail(&self) {
        let n = self.consecutive_fails.fetch_add(1, Ordering::Relaxed) + 1;
        if n == self.cfg.breaker_threshold {
            warn!(consecutive_fails = n, "risk redis: circuit breaker tripped");
        }
    }

    // ── Key helpers ───────────────────────────────────────────────────────────

    fn state_key(&self, owner_id: &str) -> String {
        format!("{}state:{}", self.cfg.key_prefix, owner_id)
    }

    fn ip_idx_key(&self, ip: IpAddr) -> String {
        format!("{}idx:ip:{}", self.cfg.key_prefix, ip)
    }

    fn fp_idx_key(&self, fp_hash: u64) -> String {
        format!("{}idx:fp:{}", self.cfg.key_prefix, fp_hash)
    }

    fn session_idx_key(&self, session_bytes: &[u8]) -> String {
        format!("{}idx:sid:{}", self.cfg.key_prefix, hex::encode(session_bytes))
    }

    /// Build index keys for a `RiskKey` (only populated axes).
    fn index_keys(&self, key: &RiskKey) -> Vec<String> {
        let mut keys = Vec::with_capacity(3);
        if let Some(ip) = key.ip {
            keys.push(self.ip_idx_key(ip));
        }
        if let Some(fp) = key.fp_hash {
            keys.push(self.fp_idx_key(fp));
        }
        if let Some(ref sess) = key.session {
            keys.push(self.session_idx_key(sess.as_bytes()));
        }
        keys
    }

    /// Generate a new UUID owner ID.
    fn mint_owner_id() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    /// Cache key from `RiskKey` (for LRU lookup).
    fn cache_key(key: &RiskKey) -> String {
        use std::fmt::Write;
        let mut s = String::new();
        if let Some(ip) = key.ip {
            let _ = write!(s, "ip:{ip}|");
        }
        if let Some(fp) = key.fp_hash {
            let _ = write!(s, "fp:{fp}|");
        }
        if let Some(ref sess) = key.session {
            let _ = write!(s, "sid:{}", hex::encode(sess.as_bytes()));
        }
        s
    }

    /// Try to get state from LRU cache (fail-open fallback).
    fn cache_lookup(&self, key: &RiskKey) -> Option<RiskState> {
        let cache_key = Self::cache_key(key);
        self.cache.lock().get(&cache_key).map(|e| e.state.clone())
    }

    /// Update LRU cache with new state.
    fn cache_update(&self, key: &RiskKey, owner_id: &str, state: &RiskState) {
        let cache_key = Self::cache_key(key);
        self.cache.lock().insert(
            cache_key,
            CacheEntry {
                state: state.clone(),
                owner_id: owner_id.to_string(),
            },
        );
    }

    // ── Redis operations ──────────────────────────────────────────────────────

    /// Resolve `owner_id` from index keys via pipelined GET, mint if not found.
    async fn resolve_or_mint_owner(&self, key: &RiskKey) -> anyhow::Result<(String, bool)> {
        let idx_keys = self.index_keys(key);
        if idx_keys.is_empty() {
            return Ok((Self::mint_owner_id(), true));
        }

        let new_owner_id = Self::mint_owner_id();
        let mut conn = self.conn.clone();

        let mut invocation = self.mint_owner_script.prepare_invoke();
        for k in &idx_keys {
            invocation.key(k);
        }
        invocation.arg(&new_owner_id).arg(self.cfg.ttl_secs);

        let res = timeout(self.cfg.op_timeout, invocation.invoke_async::<String>(&mut conn)).await;

        match res {
            Ok(Ok(json)) => {
                self.record_ok();
                let parsed: serde_json::Value =
                    serde_json::from_str(&json).context("risk redis: parse mint response")?;
                let owner_id = parsed
                    .get("owner_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("missing owner_id"))?
                    .to_string();
                let is_new = parsed
                    .get("is_new")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);
                Ok((owner_id, is_new))
            }
            Ok(Err(e)) => {
                self.record_fail();
                Err(anyhow!(e).context("risk redis: mint_or_get_owner"))
            }
            Err(_) => {
                self.record_fail();
                Err(anyhow!(
                    "risk redis: mint_or_get_owner timeout {:?}",
                    self.cfg.op_timeout
                ))
            }
        }
    }

    /// Lookup `owner_id` from multiple indices, returning all found owners.
    async fn lookup_owners(&self, key: &RiskKey) -> anyhow::Result<Vec<String>> {
        let idx_keys = self.index_keys(key);
        if idx_keys.is_empty() {
            return Ok(Vec::new());
        }

        let mut conn = self.conn.clone();
        let fut = async {
            let mut pipe = redis::pipe();
            for k in &idx_keys {
                pipe.get(k);
            }
            let results: Vec<Option<String>> = pipe.query_async(&mut conn).await?;
            Ok::<_, redis::RedisError>(results)
        };

        match timeout(self.cfg.op_timeout, fut).await {
            Ok(Ok(results)) => {
                self.record_ok();
                Ok(results.into_iter().flatten().collect())
            }
            Ok(Err(e)) => {
                self.record_fail();
                Err(anyhow!(e).context("risk redis: lookup_owners"))
            }
            Err(_) => {
                self.record_fail();
                Err(anyhow!("risk redis: lookup_owners timeout"))
            }
        }
    }

    /// Read state JSON from Redis by `owner_id`.
    async fn read_state(&self, owner_id: &str) -> anyhow::Result<Option<RiskState>> {
        let state_key = self.state_key(owner_id);
        let mut conn = self.conn.clone();

        let fut = async {
            let result: Option<String> = redis::cmd("GET").arg(&state_key).query_async(&mut conn).await?;
            Ok::<_, redis::RedisError>(result)
        };

        match timeout(self.cfg.op_timeout, fut).await {
            Ok(Ok(Some(json))) => {
                self.record_ok();
                let state: RiskState = serde_json::from_str(&json).context("risk redis: parse state")?;
                Ok(Some(state))
            }
            Ok(Ok(None)) => {
                self.record_ok();
                Ok(None)
            }
            Ok(Err(e)) => {
                self.record_fail();
                Err(anyhow!(e).context("risk redis: read_state"))
            }
            Err(_) => {
                self.record_fail();
                Err(anyhow!("risk redis: read_state timeout"))
            }
        }
    }
}

/// Response from apply Lua script.
#[derive(serde::Deserialize)]
struct ApplyResponse {
    state: RiskState,
    is_new: bool,
}

#[async_trait]
impl RiskStore for RedisRiskStore {
    async fn read(&self, key: &RiskKey) -> anyhow::Result<Option<RiskState>> {
        if key.is_empty() {
            return Ok(None);
        }

        // Try Redis first
        match self.lookup_owners(key).await {
            Ok(owners) if owners.is_empty() => Ok(None),
            Ok(owners) => {
                // Get max-score state across all found owners
                let mut max_state: Option<(String, RiskState)> = None;
                for owner_id in owners {
                    if let Ok(Some(state)) = self.read_state(&owner_id).await {
                        match &max_state {
                            None => max_state = Some((owner_id, state)),
                            Some((_, existing)) if state.clamped_score > existing.clamped_score => {
                                max_state = Some((owner_id, state));
                            }
                            _ => {}
                        }
                    }
                }
                if let Some((ref owner_id, ref state)) = max_state {
                    self.cache_update(key, owner_id, state);
                }
                Ok(max_state.map(|(_, state)| state))
            }
            Err(e) => {
                warn!(error = %e, "risk redis: read failed, checking cache");
                Ok(self.cache_lookup(key))
            }
        }
    }

    async fn apply(&self, key: &RiskKey, deltas: &[Contributor], now_ms: i64) -> anyhow::Result<ApplyResult> {
        if key.is_empty() {
            return Ok(ApplyResult {
                state: RiskState::new(now_ms),
                is_new: true,
            });
        }

        // Resolve or mint owner
        let (owner_id, _) = match self.resolve_or_mint_owner(key).await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "risk redis: resolve_or_mint failed, using cache fallback");
                if let Some(state) = self.cache_lookup(key) {
                    return Ok(ApplyResult { state, is_new: false });
                }
                return Ok(ApplyResult {
                    state: RiskState::new(now_ms),
                    is_new: true,
                });
            }
        };

        // Run apply script
        let state_key = self.state_key(&owner_id);
        let deltas_json = serde_json::to_string(deltas).context("serialize deltas")?;
        let mut conn = self.conn.clone();

        let mut invocation = self.apply_script.prepare_invoke();
        invocation
            .key(&state_key)
            .arg(now_ms)
            .arg(&deltas_json)
            .arg(self.cfg.ttl_secs)
            .arg(MIN_CLEAN_STREAK)
            .arg(DECAY_RATE)
            .arg(MAX_DECAY);

        let res = timeout(self.cfg.op_timeout, invocation.invoke_async::<String>(&mut conn)).await;

        match res {
            Ok(Ok(json)) => {
                self.record_ok();
                let response: ApplyResponse =
                    serde_json::from_str(&json).context("risk redis: parse apply response")?;
                self.cache_update(key, &owner_id, &response.state);
                Ok(ApplyResult {
                    state: response.state,
                    is_new: response.is_new,
                })
            }
            Ok(Err(e)) => {
                self.record_fail();
                warn!(error = %e, "risk redis: apply failed, using cache fallback");
                if let Some(state) = self.cache_lookup(key) {
                    return Ok(ApplyResult { state, is_new: false });
                }
                Ok(ApplyResult {
                    state: RiskState::new(now_ms),
                    is_new: true,
                })
            }
            Err(_) => {
                self.record_fail();
                warn!("risk redis: apply timeout, using cache fallback");
                if let Some(state) = self.cache_lookup(key) {
                    return Ok(ApplyResult { state, is_new: false });
                }
                Ok(ApplyResult {
                    state: RiskState::new(now_ms),
                    is_new: true,
                })
            }
        }
    }

    async fn force_max(&self, key: &RiskKey, until_ms: i64, now_ms: i64) -> anyhow::Result<()> {
        if key.is_empty() {
            return Ok(());
        }

        // Resolve or mint owner
        let (owner_id, _) = self.resolve_or_mint_owner(key).await?;
        let state_key = self.state_key(&owner_id);
        let mut conn = self.conn.clone();

        let mut invocation = self.force_max_script.prepare_invoke();
        invocation
            .key(&state_key)
            .arg(until_ms)
            .arg(now_ms)
            .arg(self.cfg.ttl_secs);

        let res = timeout(self.cfg.op_timeout, invocation.invoke_async::<String>(&mut conn)).await;

        match res {
            Ok(Ok(_)) => {
                self.record_ok();
                // Update cache with max state
                let max_state = RiskState {
                    raw_score: 100,
                    clamped_score: 100,
                    last_updated_ms: now_ms,
                    created_ms: now_ms,
                    pinned_until_ms: Some(until_ms),
                    ..Default::default()
                };
                self.cache_update(key, &owner_id, &max_state);
                Ok(())
            }
            Ok(Err(e)) => {
                self.record_fail();
                Err(anyhow!(e).context("risk redis: force_max"))
            }
            Err(_) => {
                self.record_fail();
                Err(anyhow!("risk redis: force_max timeout"))
            }
        }
    }

    /// No-op: Redis TTL handles expiration natively.
    async fn purge_expired(&self, _ttl_ms: i64, _now_ms: i64) -> anyhow::Result<usize> {
        Ok(0)
    }

    async fn reset_all(&self) -> anyhow::Result<()> {
        let pattern = format!("{}*", self.cfg.key_prefix);
        let mut conn = self.conn.clone();
        let mut deleted = 0_usize;

        // SCAN-based deletion (cooperative, bounded batches)
        let scan_fut = async {
            let mut cursor = 0_u64;
            loop {
                let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                    .arg(cursor)
                    .arg("MATCH")
                    .arg(&pattern)
                    .arg("COUNT")
                    .arg(100)
                    .query_async(&mut conn)
                    .await?;

                if !keys.is_empty() {
                    let mut pipe = redis::pipe();
                    for k in &keys {
                        pipe.del(k);
                    }
                    let _: () = pipe.query_async(&mut conn).await?;
                    deleted += keys.len();
                }

                cursor = next_cursor;
                if cursor == 0 {
                    break;
                }
            }
            Ok::<_, redis::RedisError>(deleted)
        };

        match timeout(Duration::from_secs(30), scan_fut).await {
            Ok(Ok(n)) => {
                self.record_ok();
                {
                    let mut cache = self.cache.lock();
                    cache.entries.clear();
                    cache.order.clear();
                }
                debug!(deleted = n, "risk redis: reset_all completed");
                Ok(())
            }
            Ok(Err(e)) => {
                self.record_fail();
                Err(anyhow!(e).context("risk redis: reset_all"))
            }
            Err(_) => {
                self.record_fail();
                Err(anyhow!("risk redis: reset_all timeout"))
            }
        }
    }

    async fn len(&self) -> usize {
        // Count state keys (not indices)
        let pattern = format!("{}state:*", self.cfg.key_prefix);
        let mut conn = self.conn.clone();

        let fut = async {
            let mut count = 0_usize;
            let mut cursor = 0_u64;
            loop {
                let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                    .arg(cursor)
                    .arg("MATCH")
                    .arg(&pattern)
                    .arg("COUNT")
                    .arg(1000)
                    .query_async(&mut conn)
                    .await?;
                count += keys.len();
                cursor = next_cursor;
                if cursor == 0 {
                    break;
                }
            }
            Ok::<_, redis::RedisError>(count)
        };

        match timeout(Duration::from_secs(5), fut).await {
            Ok(Ok(n)) => {
                self.record_ok();
                n
            }
            Ok(Err(e)) => {
                warn!(error = %e, "risk redis: len failed");
                self.record_fail();
                0
            }
            Err(_) => {
                warn!("risk redis: len timeout");
                self.record_fail();
                0
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_prefix() -> String {
        format!(
            "waf_risk_test_{}:",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        )
    }

    /// Integration test — runs only when `REDIS_TEST_URL` is set.
    #[tokio::test]
    async fn basic_apply_and_read() {
        use crate::risk::key::RiskKey;
        use crate::risk::state::{Contributor, ContributorKind, SeedKind};
        use std::net::Ipv4Addr;

        let Ok(url) = std::env::var("REDIS_TEST_URL") else {
            tracing::info!("skipping: REDIS_TEST_URL unset");
            return;
        };

        let store = RedisRiskStore::new(RedisRiskConfig {
            url,
            key_prefix: unique_prefix(),
            ttl_secs: 3600,
            op_timeout: Duration::from_millis(500),
            breaker_threshold: 5,
            cache_capacity: 100,
        })
        .await
        .expect("connect to REDIS_TEST_URL");

        let key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        let deltas = vec![Contributor::new(ContributorKind::Seed(SeedKind::Generic), 25, 1000)];

        let result = store.apply(&key, &deltas, 1000).await.unwrap();
        assert!(result.is_new);
        assert_eq!(result.state.clamped_score, 25);

        let read = store.read(&key).await.unwrap();
        assert!(read.is_some());
        assert_eq!(read.unwrap().clamped_score, 25);
    }

    #[tokio::test]
    async fn breaker_tracks_failures() {
        let Ok(url) = std::env::var("REDIS_TEST_URL") else {
            return;
        };

        let store = RedisRiskStore::new(RedisRiskConfig {
            url,
            key_prefix: unique_prefix(),
            breaker_threshold: 3,
            ..Default::default()
        })
        .await
        .expect("connect");

        assert!(!store.breaker_open());
        store.record_fail();
        store.record_fail();
        assert!(!store.breaker_open());
        store.record_fail();
        assert!(store.breaker_open());
        store.record_ok();
        assert!(!store.breaker_open());
    }
}
