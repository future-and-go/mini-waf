//! FR-042 — observable status for refresh-capable intel providers.
//!
//! Wraps any `IntelProvider` so the auto-refresh loop and on-demand admin
//! refreshes share the same status surface (`last_refreshed_at`,
//! `last_outcome`, `last_error`). A single `tokio::sync::Mutex` per feed
//! serialises manual + scheduled refreshes so the dashboard's "Refresh
//! now" button can return `409 Conflict` instead of stomping on an
//! in-flight automatic poll.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::Serialize;
use thiserror::Error;

use super::{IntelProvider, RefreshOutcome};

/// Distinct failure modes for `FeedStatusRegistry::refresh_one`.
///
/// The API surface needs to differentiate so the frontend can show the
/// right status (409 conflict vs 404 not-found vs 500 server error).
/// Previously merged into a single `anyhow::Error` and the handler
/// couldn't tell "refresh already running" from "feed not registered"
/// — issue #60 I6 fix.
#[derive(Debug, Error)]
pub enum RefreshError {
    /// Another refresh (manual or scheduled) is in flight for this feed.
    #[error("refresh already in flight for {0}")]
    InFlight(&'static str),
    /// Feed name is not registered with the registry.
    #[error("feed not registered: {0}")]
    NotRegistered(&'static str),
    /// Provider returned an error from `refresh()`.
    #[error("provider refresh error: {0}")]
    Provider(#[from] anyhow::Error),
}

/// High-level health classification — Frontend uses this for the badge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedHealth {
    /// Last refresh returned `Updated` or `NotModified`.
    Ok,
    /// Last refresh hit an error or no refresh has happened yet.
    Failed,
    /// No refresh attempt has been recorded yet (boot state).
    Unknown,
}

/// Per-feed observable state. Cloned out under the read-lock by accessors.
#[derive(Debug, Clone, Serialize)]
pub struct FeedState {
    pub name: &'static str,
    pub last_refreshed_at: Option<DateTime<Utc>>,
    pub last_outcome: Option<String>,
    pub last_error: Option<String>,
    pub health: FeedHealth,
}

impl FeedState {
    #[must_use]
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            last_refreshed_at: None,
            last_outcome: None,
            last_error: None,
            health: FeedHealth::Unknown,
        }
    }
}

type StateMap = Arc<RwLock<HashMap<&'static str, Arc<RwLock<FeedState>>>>>;
type LockMap = Arc<RwLock<HashMap<&'static str, Arc<tokio::sync::Mutex<()>>>>>;
type ProviderMap = Arc<RwLock<HashMap<&'static str, Arc<dyn IntelProvider>>>>;

/// Registry mapping provider name → live status.
///
/// Cheap to clone (shares the underlying `RwLock`); production wires it
/// through `Arc<AppState>` so the API and refresh loop see the same
/// snapshot. `IntelProvider` is a `dyn Trait` so it doesn't implement
/// `Debug` — we implement `Debug` manually below and omit the per-feed
/// locks + provider trait objects from the output since they leak no
/// useful information.
#[derive(Default, Clone)]
pub struct FeedStatusRegistry {
    inner: StateMap,
    locks: LockMap,
    providers: ProviderMap,
}

impl std::fmt::Debug for FeedStatusRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let feeds: Vec<&'static str> = self.inner.read().keys().copied().collect();
        let lock_count = self.locks.read().len();
        let provider_count = self.providers.read().len();
        f.debug_struct("FeedStatusRegistry")
            .field("feeds", &feeds)
            .field("lock_count", &lock_count)
            .field("provider_count", &provider_count)
            .finish()
    }
}

impl FeedStatusRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a provider so refresh + status reads are routed through the
    /// shared bookkeeping. Idempotent on `name`.
    pub fn register(&self, provider: Arc<dyn IntelProvider>) {
        let name = provider.name();
        self.inner
            .write()
            .entry(name)
            .or_insert_with(|| Arc::new(RwLock::new(FeedState::new(name))));
        self.locks
            .write()
            .entry(name)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())));
        self.providers.write().insert(name, provider);
    }

    /// Snapshot every registered feed in stable name order.
    #[must_use]
    pub fn snapshot(&self) -> Vec<FeedState> {
        let mut out: Vec<FeedState> = self.inner.read().values().map(|s| s.read().clone()).collect();
        out.sort_by(|a, b| a.name.cmp(b.name));
        out
    }

    /// Names of every registered feed — useful for refresh iteration.
    #[must_use]
    pub fn names(&self) -> Vec<&'static str> {
        let mut names: Vec<&'static str> = self.inner.read().keys().copied().collect();
        names.sort_unstable();
        names
    }

    /// Run `provider.refresh()` once and record the outcome. Distinct
    /// failure modes (in-flight, not-registered, provider error) are
    /// surfaced via `RefreshError` so the API handler can map each to the
    /// right HTTP status code (issue #60 I6 fix).
    pub async fn refresh_one(&self, name: &'static str) -> Result<RefreshOutcome, RefreshError> {
        let provider = self
            .providers
            .read()
            .get(name)
            .cloned()
            .ok_or(RefreshError::NotRegistered(name))?;
        let lock = self
            .locks
            .read()
            .get(name)
            .cloned()
            .ok_or(RefreshError::NotRegistered(name))?;
        let _guard = lock.try_lock().map_err(|_| RefreshError::InFlight(name))?;

        let outcome = provider.refresh().await;
        let entry = self.inner.read().get(name).cloned();
        if let Some(state_lock) = entry {
            let mut state = state_lock.write();
            state.last_refreshed_at = Some(Utc::now());
            match &outcome {
                Ok(RefreshOutcome::Updated) => {
                    state.last_outcome = Some("updated".into());
                    state.last_error = None;
                    state.health = FeedHealth::Ok;
                }
                Ok(RefreshOutcome::NotModified) => {
                    state.last_outcome = Some("not_modified".into());
                    state.last_error = None;
                    state.health = FeedHealth::Ok;
                }
                Ok(RefreshOutcome::Failed(err)) => {
                    state.last_outcome = Some("failed".into());
                    state.last_error = Some(err.to_string());
                    state.health = FeedHealth::Failed;
                }
                Err(err) => {
                    state.last_outcome = Some("error".into());
                    state.last_error = Some(err.to_string());
                    state.health = FeedHealth::Failed;
                }
            }
        }
        outcome.map_err(RefreshError::Provider)
    }

    /// Refresh every registered feed sequentially. Skips a feed whose lock
    /// is held by another in-flight refresh and continues with the rest.
    pub async fn refresh_all(&self) -> Vec<(&'static str, Result<RefreshOutcome, RefreshError>)> {
        let names = self.names();
        let mut out = Vec::with_capacity(names.len());
        for name in names {
            let res = self.refresh_one(name).await;
            out.push((name, res));
        }
        out
    }
}

/// Decorator that mirrors provider behaviour into a `FeedStatusRegistry`.
///
/// The background refresh loop ticks update the registry too via this
/// wrapper; without it, only manual refreshes (via the API) would update
/// status.
pub struct TrackedProvider<P> {
    inner: Arc<P>,
    registry: FeedStatusRegistry,
}

impl<P> TrackedProvider<P>
where
    P: IntelProvider + 'static,
{
    pub fn new(inner: Arc<P>, registry: FeedStatusRegistry) -> Self {
        let dyn_provider: Arc<dyn IntelProvider> = inner.clone() as Arc<dyn IntelProvider>;
        registry.register(dyn_provider);
        Self { inner, registry }
    }
}

#[async_trait]
impl<P> IntelProvider for TrackedProvider<P>
where
    P: IntelProvider + 'static,
{
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    async fn refresh(&self) -> Result<RefreshOutcome> {
        // Route through the registry so concurrent refreshes get serialised
        // and the status record stays in sync with reality. `IntelProvider`
        // trait returns `anyhow::Result`, so collapse `RefreshError`
        // variants back into anyhow at this boundary.
        self.registry
            .refresh_one(self.inner.name())
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct AlwaysOk {
        name: &'static str,
        calls: AtomicU32,
    }

    #[async_trait]
    impl IntelProvider for AlwaysOk {
        fn name(&self) -> &'static str {
            self.name
        }
        async fn refresh(&self) -> Result<RefreshOutcome> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(RefreshOutcome::Updated)
        }
    }

    struct AlwaysErr;

    #[async_trait]
    impl IntelProvider for AlwaysErr {
        fn name(&self) -> &'static str {
            "always_err"
        }
        async fn refresh(&self) -> Result<RefreshOutcome> {
            Err(anyhow::anyhow!("boom"))
        }
    }

    #[tokio::test]
    async fn empty_registry_returns_no_snapshot() {
        let reg = FeedStatusRegistry::new();
        assert!(reg.snapshot().is_empty());
        assert!(reg.names().is_empty());
    }

    #[tokio::test]
    async fn register_then_snapshot_returns_unknown_state() {
        let reg = FeedStatusRegistry::new();
        let provider: Arc<dyn IntelProvider> = Arc::new(AlwaysOk {
            name: "demo",
            calls: AtomicU32::new(0),
        });
        reg.register(provider);
        let snap = reg.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].name, "demo");
        assert!(matches!(snap[0].health, FeedHealth::Unknown));
        assert!(snap[0].last_refreshed_at.is_none());
    }

    #[tokio::test]
    async fn refresh_one_marks_ok_on_success() {
        let reg = FeedStatusRegistry::new();
        let provider: Arc<dyn IntelProvider> = Arc::new(AlwaysOk {
            name: "ok_feed",
            calls: AtomicU32::new(0),
        });
        reg.register(provider);
        let out = reg.refresh_one("ok_feed").await.expect("refresh");
        assert!(matches!(out, RefreshOutcome::Updated));
        let snap = reg.snapshot();
        assert_eq!(snap[0].health, FeedHealth::Ok);
        assert_eq!(snap[0].last_outcome.as_deref(), Some("updated"));
    }

    #[tokio::test]
    async fn refresh_one_marks_failed_on_error() {
        let reg = FeedStatusRegistry::new();
        let provider: Arc<dyn IntelProvider> = Arc::new(AlwaysErr);
        reg.register(provider);
        let res = reg.refresh_one("always_err").await;
        assert!(res.is_err());
        let snap = reg.snapshot();
        assert_eq!(snap[0].health, FeedHealth::Failed);
        assert_eq!(snap[0].last_outcome.as_deref(), Some("error"));
        assert!(snap[0].last_error.is_some());
    }

    #[tokio::test]
    async fn refresh_all_visits_every_feed() {
        let reg = FeedStatusRegistry::new();
        let a: Arc<dyn IntelProvider> = Arc::new(AlwaysOk {
            name: "alpha",
            calls: AtomicU32::new(0),
        });
        let b: Arc<dyn IntelProvider> = Arc::new(AlwaysErr);
        reg.register(a);
        reg.register(b);

        let outs = reg.refresh_all().await;
        assert_eq!(outs.len(), 2);
        let snap = reg.snapshot();
        assert!(snap.iter().any(|s| s.name == "alpha" && s.health == FeedHealth::Ok));
        assert!(
            snap.iter()
                .any(|s| s.name == "always_err" && s.health == FeedHealth::Failed)
        );
    }

    #[tokio::test]
    async fn refresh_unknown_feed_returns_error() {
        let reg = FeedStatusRegistry::new();
        let res = reg.refresh_one("ghost").await;
        assert!(res.is_err());
    }
}
