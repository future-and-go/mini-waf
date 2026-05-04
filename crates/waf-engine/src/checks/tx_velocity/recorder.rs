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

use super::config::TxVelocityConfig;
use super::session_key::SessionKey;
use super::{EndpointRole, Event};

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

/// Per-actor transaction store. Holds an `ArcSwap<TxVelocityConfig>` so
/// the janitor reads the current TTL on every tick (hot-reload friendly).
pub struct TxStore {
    actors: DashMap<SessionKey, ActorTx>,
    anchor: Instant,
    cfg: Arc<ArcSwap<TxVelocityConfig>>,
}

impl TxStore {
    #[must_use]
    pub fn new(cfg: Arc<ArcSwap<TxVelocityConfig>>) -> Self {
        let cpus = std::thread::available_parallelism().map_or(8, std::num::NonZeroUsize::get);
        let shards = (cpus * 2).next_power_of_two();
        Self {
            actors: DashMap::with_capacity_and_shard_amount(0, shards),
            anchor: Instant::now(),
            cfg,
        }
    }

    /// Saturating-cast monotonic ms since `anchor`. `u128 → u64` saturates
    /// at `u64::MAX` (~585 million years) — defensive only.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        u64::try_from(self.anchor.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Append an event for `key`. Skips when `role == None` (path didn't
    /// match any rule) — caller is free to call unconditionally.
    pub fn record(&self, key: SessionKey, role: EndpointRole, ok: bool) {
        if matches!(role, EndpointRole::None) {
            return;
        }
        let event = Event {
            role,
            ts_ms: self.now_ms(),
            ok,
        };
        self.actors.entry(key).or_default().record(event);
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
        s.record(key("a"), EndpointRole::None, true);
        assert!(s.snapshot(&key("a")).is_none());
        assert!(s.is_empty());
    }

    #[test]
    fn record_appends_for_known_role() {
        let s = TxStore::new(cfg(600));
        let k = key("a");
        s.record(k.clone(), EndpointRole::Login, true);
        let snap = s.snapshot(&k).expect("snapshot present");
        assert_eq!(snap.events.len(), 1);
        assert_eq!(snap.events.first().map(|e| e.role), Some(EndpointRole::Login));
    }

    #[test]
    fn ring_caps_at_window_and_drops_oldest() {
        let s = TxStore::new(cfg(600));
        let k = key("b");
        for _ in 0..(WINDOW + 4) {
            s.record(k.clone(), EndpointRole::Deposit, true);
        }
        let snap = s.snapshot(&k).expect("snapshot");
        assert_eq!(snap.events.len(), WINDOW);
    }

    #[test]
    fn mark_signal_updates_cooldown_marker() {
        let s = TxStore::new(cfg(600));
        let k = key("c");
        s.record(k.clone(), EndpointRole::Otp, true);
        s.mark_signal(&k, 12_345);
        let snap = s.snapshot(&k).expect("snapshot");
        assert_eq!(snap.last_signal_ms, 12_345);
    }

    #[test]
    fn purge_expired_removes_idle_actors() {
        // ttl=0 ⇒ next tick treats every actor as expired.
        let s = TxStore::new(cfg(0));
        let k = key("d");
        s.record(k.clone(), EndpointRole::Login, true);
        std::thread::sleep(Duration::from_millis(2));
        let purged = s.purge_expired();
        assert_eq!(purged, 1);
        assert!(s.snapshot(&k).is_none());
    }

    #[test]
    fn purge_keeps_fresh_actors() {
        let s = TxStore::new(cfg(3_600));
        let k = key("e");
        s.record(k.clone(), EndpointRole::Login, true);
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
                    s.record(k, EndpointRole::Withdrawal, true);
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
}
