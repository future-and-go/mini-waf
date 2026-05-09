//! `CacheBackend` — unified async interface over every cache storage implementation.
//!
//! Implementors: `MokaStore` (in-process LRU), `ValkeyStore` (external Valkey/Redis),
//! `CircuitBreakerStore` (wraps Valkey with moka fallback).
//!
//! All methods are **infallible** by design: each implementor must absorb errors
//! internally, degrade gracefully (log + return `None` / `0`), and never panic.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

// ── Serializable response type ────────────────────────────────────────────────

/// A cached HTTP response. Used by all backend implementations as the value
/// stored under each cache key.
///
/// `body` is serialized as base64 when going through Valkey (JSON wire format).
#[derive(Debug, Clone)]
pub struct CachedResponse {
    pub status: u16,
    /// Response headers as (name, value) pairs.
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
    /// Seconds until expiry (from insertion time; set by the resolver).
    pub max_age: u64,
}

/// Wire representation used for JSON serialization to/from Valkey.
#[derive(Serialize, Deserialize)]
pub(crate) struct WireCachedResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    #[serde(with = "base64_field")]
    pub body: Vec<u8>,
    pub max_age: u64,
}

impl From<&CachedResponse> for WireCachedResponse {
    fn from(r: &CachedResponse) -> Self {
        Self {
            status: r.status,
            headers: r.headers.clone(),
            body: r.body.to_vec(),
            max_age: r.max_age,
        }
    }
}

impl From<WireCachedResponse> for CachedResponse {
    fn from(w: WireCachedResponse) -> Self {
        Self {
            status: w.status,
            headers: w.headers,
            body: Bytes::from(w.body),
            max_age: w.max_age,
        }
    }
}

mod base64_field {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s: &str = serde::Deserialize::deserialize(d)?;
        STANDARD.decode(s).map_err(D::Error::custom)
    }
}

// ── Health ────────────────────────────────────────────────────────────────────

/// Health status returned by `CacheBackend::ping`.
#[derive(Debug, Clone, Serialize)]
pub struct BackendHealth {
    /// `true` when the backend is reachable and responsive.
    pub ok: bool,
    /// Round-trip time for a `PING` command in microseconds.
    pub latency_us: u64,
    /// Human-readable error when `ok = false`.
    pub error: Option<String>,
}

impl BackendHealth {
    pub const fn healthy(latency_us: u64) -> Self {
        Self {
            ok: true,
            latency_us,
            error: None,
        }
    }

    pub fn unhealthy(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            latency_us: 0,
            error: Some(error.into()),
        }
    }
}

// ── Extended stats ────────────────────────────────────────────────────────────

/// Backend-specific extended statistics returned by the `/api/cache/backend`
/// endpoint. Fields absent for the `memory` backend use `None`.
#[derive(Debug, Clone, Serialize)]
pub struct BackendInfo {
    /// Backend kind label: `"memory"`, `"embedded"`, `"standalone"`, `"cluster"`.
    pub backend: String,
    /// Valkey/Redis server version string (e.g. `"7.2.4"`). `None` for memory.
    pub valkey_version: Option<String>,
    /// `true` if at least one node is reachable.
    pub connected: bool,
    /// Cluster nodes (non-empty for `standalone`/`cluster`/`embedded`).
    pub nodes: Vec<NodeSummary>,
    /// Memory currently used by the backend in bytes.
    pub memory_used_bytes: Option<u64>,
    /// Maximum memory limit in bytes (`maxmemory` config). `None` = unlimited.
    pub memory_max_bytes: Option<u64>,
    /// Memory fragmentation ratio (RSS / used); `None` for memory backend.
    pub memory_fragmentation_ratio: Option<f64>,
    /// Instantaneous commands processed per second.
    pub ops_per_sec: Option<u64>,
    /// Active client connections to the Valkey server.
    pub connected_clients: Option<u32>,
    /// Keyspace summary: db → (keys, expires).
    pub keyspace: std::collections::HashMap<String, KeyspaceSummary>,
    /// Backend health from the most recent ping.
    pub health: BackendHealth,
    /// Circuit-breaker state: `"closed"`, `"open"`, or `"half_open"`.
    pub circuit_breaker: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeSummary {
    pub addr: String,
    pub role: String,
    pub slots: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct KeyspaceSummary {
    pub keys: u64,
    pub expires: u64,
}

// ── Trait ─────────────────────────────────────────────────────────────────────

/// Unified interface over every cache storage implementation.
///
/// All methods are async and infallible. Implementations MUST:
/// - Handle errors internally (log with `tracing::warn!` then degrade).
/// - Never `panic!`, `unwrap()`, or `expect()`.
/// - Never block the executor thread.
#[async_trait]
pub trait CacheBackend: Send + Sync + 'static {
    /// Fetch a cached entry. Returns `None` on miss or error.
    async fn get(&self, key: &str) -> Option<Arc<CachedResponse>>;

    /// Store an entry with the given TTL and tag set.
    /// Returns `true` when the entry was successfully stored.
    ///
    /// `tags` are used for tag-based purge. Each tag maps to the key so that
    /// `purge_by_tag` can find and evict all affected entries efficiently.
    async fn put(&self, key: &str, value: CachedResponse, ttl_secs: u64, tags: &[Arc<str>]) -> bool;

    /// Remove a single key. No-op if the key does not exist.
    async fn remove(&self, key: &str);

    /// Remove all entries tagged with `tag`. Returns count removed.
    async fn purge_by_tag(&self, tag: &str) -> usize;

    /// Remove all entries whose route-rule tag matches `route_id`.
    /// Equivalent to `purge_by_tag(route_id)` — route IDs are auto-tagged
    /// by `RouteRuleGate` and stored in the same tag index.
    async fn purge_by_route_id(&self, route_id: &str) -> usize;

    /// Remove all entries whose cache key contains the given `host` segment.
    async fn purge_host(&self, host: &str) -> usize;

    /// Evict every entry. Async to allow batched DEL in Valkey.
    async fn flush(&self);

    /// Approximate number of entries currently stored.
    fn entry_count(&self) -> u64;

    /// Number of distinct tag→key mappings in the local tag index.
    /// For Valkey, this counts the local reverse-index entries (estimated).
    fn tag_index_size(&self) -> usize;

    /// Probe the backend and return a health snapshot.
    async fn ping(&self) -> BackendHealth;

    /// Collect backend-specific info for the `/api/cache/backend` endpoint.
    async fn backend_info(&self) -> BackendInfo;

    /// Per-tag counts (keys associated with each tag) for dashboard top-routes.
    async fn tag_entry_counts(&self) -> Vec<(String, u64)>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_from_cached_response_clones_fields() {
        let cr = CachedResponse {
            status: 201,
            headers: vec![("x-foo".into(), "bar".into())],
            body: Bytes::from_static(b"hello"),
            max_age: 42,
        };
        let w = WireCachedResponse::from(&cr);
        assert_eq!(w.status, 201);
        assert_eq!(w.headers, vec![("x-foo".to_string(), "bar".to_string())]);
        assert_eq!(w.body, b"hello".to_vec());
        assert_eq!(w.max_age, 42);
    }

    #[test]
    fn cached_response_from_wire_round_trips_body() {
        let w = WireCachedResponse {
            status: 304,
            headers: vec![("etag".into(), "\"abc\"".into())],
            body: vec![1, 2, 3, 4],
            max_age: 7,
        };
        let cr: CachedResponse = w.into();
        assert_eq!(cr.status, 304);
        assert_eq!(cr.headers.len(), 1);
        assert_eq!(cr.body.as_ref(), &[1u8, 2, 3, 4]);
        assert_eq!(cr.max_age, 7);
    }

    #[test]
    fn wire_serde_json_round_trip_preserves_body_via_base64() {
        let original = CachedResponse {
            status: 200,
            headers: vec![
                ("content-type".into(), "application/octet-stream".into()),
                ("x-bin".into(), "y".into()),
            ],
            body: Bytes::from_static(&[0u8, 1, 2, 250, 251, 252, 253, 254, 255]),
            max_age: 600,
        };
        let wire = WireCachedResponse::from(&original);
        let json = serde_json::to_string(&wire).expect("serialize");
        // base64 of [0,1,2,250,251,252,253,254,255] = "AAEC+vv8/f7/"
        assert!(json.contains("\"AAEC+vv8/f7/\""), "json = {json}");

        let back: WireCachedResponse = serde_json::from_str(&json).expect("deserialize");
        let restored: CachedResponse = back.into();
        assert_eq!(restored.status, original.status);
        assert_eq!(restored.headers, original.headers);
        assert_eq!(restored.body, original.body);
        assert_eq!(restored.max_age, original.max_age);
    }

    #[test]
    fn wire_deserialize_rejects_invalid_base64() {
        let bad = r#"{"status":200,"headers":[],"body":"!!!not-base64!!!","max_age":1}"#;
        let res: Result<WireCachedResponse, _> = serde_json::from_str(bad);
        assert!(res.is_err(), "invalid base64 must error, not panic");
    }

    #[test]
    fn backend_health_healthy_const() {
        let h = BackendHealth::healthy(99);
        assert!(h.ok);
        assert_eq!(h.latency_us, 99);
        assert!(h.error.is_none());
    }

    #[test]
    fn backend_health_unhealthy_helper() {
        let h = BackendHealth::unhealthy("down");
        assert!(!h.ok);
        assert_eq!(h.error.as_deref(), Some("down"));
    }
}
