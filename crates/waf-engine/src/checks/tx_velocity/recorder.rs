//! FR-012 phase-01 — lock-free per-actor `TxStore`.
//!
//! `DashMap<SessionKey, ActorTx>` keyed by `SessionKey`. Append is O(1) via
//! the entry API. The ring buffer is hand-rolled (mirrors
//! `device_fp::behavior::state::ActorBehavior`) so we avoid pulling in
//! `arrayvec` / `arraydeque` for a 16-slot buffer.
//!
//! Time is monotonic ms since `anchor: Instant`; wall-clock jumps cannot
//! produce negative intervals. The janitor purges actors idle longer than
//! `session_ttl_secs`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use tokio::task::JoinHandle;

use super::classifier::Classifier;
use super::config::TxVelocityConfig;
use super::session_key::{SessionIdent, SessionKey};
use super::{EndpointRole, Event};
use crate::device_fp::aggregator::{NoopAggregator, RiskAggregator};
use crate::device_fp::signal::Signal;
use crate::device_fp::types::FpKey;

/// `SessionKey` → `FpKey` for risk-aggregator submissions.
///
/// Cookie-based identities have no fingerprint payload, so they collapse to
/// the default (empty) `FpKey`. Aggregators that care about per-session
/// dedupe should look at signal payloads, not the key, in that case.
fn fp_key_for_submission(key: &SessionKey) -> FpKey {
    match &key.ident {
        SessionIdent::Fingerprint(fp) => fp.clone(),
        SessionIdent::Cookie(_) => FpKey::default(),
    }
}

/// Sample ring depth. Matches the figure in the plan; classifiers in
/// Phase 2 will read whole snapshots, never the live struct.
pub const WINDOW: usize = 16;

/// Per-actor transaction state. `record` is O(1); `samples()` yields
/// oldest → newest. `last_signal_ms` lets Phase 2 enforce per-actor
/// cooldown without touching the ring.
#[derive(Clone, Debug)]
pub struct ActorTx {
    events: [Option<Event>; WINDOW],
    head: usize,
    len: usize,
    pub updated_ms: u64,
    pub last_signal_ms: u64,
}

impl ActorTx {
    pub const fn new() -> Self {
        Self {
            events: [None; WINDOW],
            head: 0,
            len: 0,
            updated_ms: 0,
            last_signal_ms: 0,
        }
    }

    pub fn record(&mut self, event: Event) {
        if let Some(slot) = self.events.get_mut(self.head) {
            *slot = Some(event);
        }
        self.head = (self.head + 1) % WINDOW;
        if self.len < WINDOW {
            self.len += 1;
        }
        self.updated_ms = event.ts_ms;
    }

    /// Iterate events oldest → newest. `Event: Copy`, so cheap.
    pub fn events(&self) -> impl Iterator<Item = Event> + '_ {
        let start = if self.len < WINDOW { 0 } else { self.head };
        (0..self.len).filter_map(move |i| self.events.get((start + i) % WINDOW).copied().flatten())
    }

    /// Live count (≤ WINDOW). Diagnostic helper.
    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for ActorTx {
    fn default() -> Self {
        Self::new()
    }
}

/// Bounded snapshot handed to classifiers (Phase 2). Cloned out of the
/// shard so classifiers never hold a `DashMap` guard while evaluating.
#[derive(Clone, Debug)]
pub struct ActorTxSnapshot {
    pub events: Vec<Event>,
    pub updated_ms: u64,
    pub last_signal_ms: u64,
}

/// Per-actor transaction store.
///
/// Holds an `ArcSwap<TxVelocityConfig>` so the janitor reads the current TTL
/// on every tick (hot-reload friendly). `classifiers` and `aggregator` are
/// immutable for the store's lifetime — hot-reloads change thresholds via
/// `cfg`, never the strategy list.
pub struct TxStore {
    actors: DashMap<SessionKey, ActorTx>,
    anchor: Instant,
    cfg: Arc<ArcSwap<TxVelocityConfig>>,
    classifiers: Vec<Arc<dyn Classifier>>,
    aggregator: Arc<dyn RiskAggregator>,
}

impl TxStore {
    /// Build a store with no classifiers and a no-op aggregator. Existing
    /// Phase 1 callers (and unit tests) keep working unchanged; production
    /// wire-up uses [`Self::with_pipeline`] at startup.
    #[must_use]
    pub fn new(cfg: Arc<ArcSwap<TxVelocityConfig>>) -> Self {
        Self::with_pipeline(cfg, Vec::new(), Arc::new(NoopAggregator))
    }

    /// Full constructor — classifier list + aggregator are fixed for the
    /// store's lifetime.
    #[must_use]
    pub fn with_pipeline(
        cfg: Arc<ArcSwap<TxVelocityConfig>>,
        classifiers: Vec<Arc<dyn Classifier>>,
        aggregator: Arc<dyn RiskAggregator>,
    ) -> Self {
        let cpus = std::thread::available_parallelism().map_or(8, std::num::NonZeroUsize::get);
        let shards = (cpus * 2).next_power_of_two();
        Self {
            actors: DashMap::with_capacity_and_shard_amount(0, shards),
            anchor: Instant::now(),
            cfg,
            classifiers,
            aggregator,
        }
    }

    /// Saturating-cast monotonic ms since `anchor`. `u128 → u64` saturates
    /// at `u64::MAX` (~585 million years) — defensive only.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        u64::try_from(self.anchor.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Append an event for `key` and run the classifier pipeline. Skips
    /// when `role == None` (path didn't match any rule) — caller is free to
    /// call unconditionally.
    ///
    /// Classifier evaluation is gated by per-actor cooldown
    /// (`cfg.signal_cooldown_ms`); within the cooldown window the
    /// recorder still appends the event but skips evaluation entirely.
    /// Submission to the aggregator is fire-and-forget (`tokio::spawn`).
    pub fn record(&self, key: &SessionKey, role: EndpointRole, ok: bool) {
        if matches!(role, EndpointRole::None) {
            return;
        }
        let now_ms = self.now_ms();
        let event = Event {
            role,
            ts_ms: now_ms,
            ok,
        };

        // Append + capture cooldown marker without holding the shard guard
        // across classifier evaluation (deadlock-safe).
        let last_signal_ms = {
            let mut entry = self.actors.entry(key.clone()).or_default();
            entry.record(event);
            entry.last_signal_ms
        };

        if self.classifiers.is_empty() {
            return;
        }
        let cfg = self.cfg.load_full();
        if !cfg.enabled {
            return;
        }
        if now_ms.saturating_sub(last_signal_ms) < cfg.signal_cooldown_ms && last_signal_ms != 0 {
            return;
        }

        let Some(snap) = self.snapshot(key) else {
            return; // Race with purge: drop and move on.
        };
        let signals: Vec<Signal> = self
            .classifiers
            .iter()
            .filter_map(|c| c.evaluate(&snap, now_ms, &cfg))
            .collect();
        if signals.is_empty() {
            return;
        }

        // `0` is the sentinel for "never fired" — bump to 1 if record-time
        // happened to hit the anchor instant exactly.
        self.mark_signal(key, now_ms.max(1));

        let fp_key = fp_key_for_submission(key);
        let aggregator = Arc::clone(&self.aggregator);
        tokio::spawn(async move {
            aggregator.submit(&fp_key, &signals).await;
        });
    }

    /// Clone the bounded actor state. Returns `None` if unseen.
    #[must_use]
    pub fn snapshot(&self, key: &SessionKey) -> Option<ActorTxSnapshot> {
        self.actors.get(key).map(|r| {
            let v = r.value();
            ActorTxSnapshot {
                events: v.events().collect(),
                updated_ms: v.updated_ms,
                last_signal_ms: v.last_signal_ms,
            }
        })
    }

    /// Mark that a signal was emitted for `key` at `now_ms`. Phase 2
    /// classifiers use this for per-actor cooldown.
    pub fn mark_signal(&self, key: &SessionKey, now_ms: u64) {
        if let Some(mut entry) = self.actors.get_mut(key) {
            entry.last_signal_ms = now_ms;
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.actors.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.actors.is_empty()
    }

    /// Drop actors idle longer than `session_ttl_secs`. Returns count purged.
    pub fn purge_expired(&self) -> usize {
        let ttl_ms = self.cfg.load().session_ttl_secs.saturating_mul(1000);
        let cutoff = self.now_ms().saturating_sub(ttl_ms);
        let mut purged = 0_usize;
        self.actors.retain(|_, v| {
            if v.updated_ms < cutoff {
                purged += 1;
                false
            } else {
                true
            }
        });
        purged
    }

    /// Spawn a background TTL janitor. Aborts on `JoinHandle::abort` /
    /// drop. Mirrors `device_fp::behavior::recorder::Recorder::spawn_janitor`.
    #[must_use]
    pub fn spawn_janitor(self: Arc<Self>, period: Duration) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(period);
            tick.tick().await; // first tick fires immediately
            loop {
                tick.tick().await;
                self.purge_expired();
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::tx_velocity::session_key::SessionIdent;

    fn cfg(ttl_secs: u64) -> Arc<ArcSwap<TxVelocityConfig>> {
        Arc::new(ArcSwap::from_pointee(TxVelocityConfig {
            session_ttl_secs: ttl_secs,
            ..TxVelocityConfig::default()
        }))
    }

    fn key(tag: &str) -> SessionKey {
        SessionKey {
            host: "h".to_string(),
            ident: SessionIdent::Cookie(tag.to_string()),
        }
    }

    #[test]
    fn record_skips_role_none() {
        let s = TxStore::new(cfg(600));
        s.record(&key("a"), EndpointRole::None, true);
        assert!(s.snapshot(&key("a")).is_none());
        assert!(s.is_empty());
    }

    #[test]
    fn record_appends_for_known_role() {
        let s = TxStore::new(cfg(600));
        let k = key("a");
        s.record(&k, EndpointRole::Login, true);
        let snap = s.snapshot(&k).expect("snapshot present");
        assert_eq!(snap.events.len(), 1);
        assert_eq!(snap.events.first().map(|e| e.role), Some(EndpointRole::Login));
    }

    #[test]
    fn ring_caps_at_window_and_drops_oldest() {
        let s = TxStore::new(cfg(600));
        let k = key("b");
        for _ in 0..(WINDOW + 4) {
            s.record(&k, EndpointRole::Deposit, true);
        }
        let snap = s.snapshot(&k).expect("snapshot");
        assert_eq!(snap.events.len(), WINDOW);
    }

    #[test]
    fn mark_signal_updates_cooldown_marker() {
        let s = TxStore::new(cfg(600));
        let k = key("c");
        s.record(&k, EndpointRole::Otp, true);
        s.mark_signal(&k, 12_345);
        let snap = s.snapshot(&k).expect("snapshot");
        assert_eq!(snap.last_signal_ms, 12_345);
    }

    #[test]
    fn purge_expired_removes_idle_actors() {
        // ttl=0 ⇒ next tick treats every actor as expired.
        let s = TxStore::new(cfg(0));
        let k = key("d");
        s.record(&k, EndpointRole::Login, true);
        std::thread::sleep(Duration::from_millis(2));
        let purged = s.purge_expired();
        assert_eq!(purged, 1);
        assert!(s.snapshot(&k).is_none());
    }

    #[test]
    fn purge_keeps_fresh_actors() {
        let s = TxStore::new(cfg(3_600));
        let k = key("e");
        s.record(&k, EndpointRole::Login, true);
        let purged = s.purge_expired();
        assert_eq!(purged, 0);
        assert!(s.snapshot(&k).is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_inserts_no_panic() {
        let s = Arc::new(TxStore::new(cfg(600)));
        let mut handles = Vec::new();
        for task_id in 0..50u32 {
            let s = Arc::clone(&s);
            handles.push(tokio::spawn(async move {
                for i in 0..50u32 {
                    let k = key(&format!("t{task_id}-k{}", i % 5));
                    s.record(&k, EndpointRole::Withdrawal, true);
                }
            }));
        }
        for h in handles {
            h.await.expect("task should not panic");
        }
        assert!(!s.is_empty());
    }

    #[tokio::test]
    async fn janitor_runs_without_panic() {
        let s = Arc::new(TxStore::new(cfg(3_600)));
        let h = Arc::clone(&s).spawn_janitor(Duration::from_millis(10));
        tokio::time::sleep(Duration::from_millis(50)).await;
        h.abort();
    }

    // ─── Phase 2 pipeline tests ─────────────────────────────────────────────

    use crate::checks::tx_velocity::classifiers::default_classifiers;
    use crate::checks::tx_velocity::config::{ClassifierConfigs, SequenceCfg, VelocityCfg};
    use crate::device_fp::aggregator::LoggingAggregator;
    use crate::device_fp::types::{FingerprintValue, FpKey};

    fn cfg_pipeline(cooldown_ms: u64) -> Arc<ArcSwap<TxVelocityConfig>> {
        Arc::new(ArcSwap::from_pointee(TxVelocityConfig {
            enabled: true,
            signal_cooldown_ms: cooldown_ms,
            classifiers: ClassifierConfigs {
                sequence: Some(SequenceCfg { min_human_ms: 1_500 }),
                withdrawal_velocity: Some(VelocityCfg {
                    max_count: 2,
                    window_ms: 60_000,
                }),
                limit_change_velocity: None,
            },
            ..TxVelocityConfig::default()
        }))
    }

    /// Spin briefly so the fire-and-forget `tokio::spawn` task lands.
    async fn flush() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    #[tokio::test]
    async fn pipeline_emits_signal_on_velocity_breach() {
        let cfg = cfg_pipeline(0);
        let agg = LoggingAggregator::new(8);
        let store = TxStore::with_pipeline(
            cfg,
            default_classifiers(&TxVelocityConfig::default()),
            Arc::new(agg.clone()),
        );

        let k = key("velocity");
        for _ in 0..3 {
            store.record(&k, EndpointRole::Withdrawal, true);
        }
        flush().await;

        let snap = agg.snapshot();
        assert!(
            snap.iter().any(|s| matches!(
                s.signals.first(),
                Some(Signal::WithdrawalVelocity { count, .. }) if *count >= 3
            )),
            "expected WithdrawalVelocity in {snap:?}",
        );
    }

    #[tokio::test]
    async fn pipeline_cooldown_suppresses_duplicate_signals() {
        // Long cooldown — two breaching record() bursts should produce one
        // submission, not two.
        let cfg = cfg_pipeline(60_000);
        let agg = LoggingAggregator::new(8);
        let store = TxStore::with_pipeline(
            cfg,
            default_classifiers(&TxVelocityConfig::default()),
            Arc::new(agg.clone()),
        );

        let k = key("cooldown");
        for _ in 0..3 {
            store.record(&k, EndpointRole::Withdrawal, true);
        }
        flush().await;
        // Trigger again: still over threshold, but cooldown should mute it.
        for _ in 0..3 {
            store.record(&k, EndpointRole::Withdrawal, true);
        }
        flush().await;

        assert_eq!(agg.snapshot().len(), 1, "cooldown failed: {:?}", agg.snapshot());
    }

    #[tokio::test]
    async fn pipeline_disabled_skips_classifier_submission() {
        let cfg = Arc::new(ArcSwap::from_pointee(TxVelocityConfig {
            enabled: false,
            classifiers: ClassifierConfigs {
                withdrawal_velocity: Some(VelocityCfg {
                    max_count: 0,
                    window_ms: 60_000,
                }),
                ..ClassifierConfigs::default()
            },
            ..TxVelocityConfig::default()
        }));
        let agg = LoggingAggregator::new(8);
        let store = TxStore::with_pipeline(
            cfg,
            default_classifiers(&TxVelocityConfig::default()),
            Arc::new(agg.clone()),
        );

        store.record(&key("disabled"), EndpointRole::Withdrawal, true);
        flush().await;
        assert!(agg.snapshot().is_empty());
    }

    #[tokio::test]
    async fn pipeline_uses_fingerprint_when_session_is_fp() {
        let cfg = cfg_pipeline(0);
        let agg = LoggingAggregator::new(8);
        let store = TxStore::with_pipeline(
            cfg,
            default_classifiers(&TxVelocityConfig::default()),
            Arc::new(agg.clone()),
        );

        let fp = FpKey {
            ja3: Some(FingerprintValue::new("ja3-fp")),
            ..FpKey::default()
        };
        let k = SessionKey {
            host: "h".to_string(),
            ident: SessionIdent::Fingerprint(fp.clone()),
        };
        for _ in 0..3 {
            store.record(&k, EndpointRole::Withdrawal, true);
        }
        flush().await;

        let snap = agg.snapshot();
        assert!(
            snap.iter().any(|s| s.key == fp),
            "submission should carry fp key: {snap:?}"
        );
    }
}
