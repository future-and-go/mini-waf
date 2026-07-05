//! Ban action with TTL escalation.
//!
//! [`BanAction`] tracks offenses per IP and applies escalating bans:
//! - 1st offense: 60s ban, +30 risk
//! - 2nd offense: 5m ban, +50 risk
//! - 3rd+ offense: 1h ban, +100 risk (clamped)
//!
//! Offense counter resets after 1h window. Uses [`DynamicBanTable`] for
//! TTL-aware IP blocking separate from static config-based blacklists.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use tracing::warn;

use crate::checks::ddos::detector::DetectorVerdict;
use crate::checks::ddos::store::CounterStore;

use super::{ActionExecutor, ActionResult};

/// Per-entry state stored in the [`DynamicBanTable`].
///
/// Carries the metadata the admin ban table renders (`ban_level`, `last_rps`,
/// `reason`) alongside the expiry. Computed at ban time in
/// [`BanAction::execute`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BanState {
    /// Expiry timestamp (epoch ms).
    pub expires_ms: i64,
    /// Offense step that produced this ban (1-indexed; 0 = unknown/manual).
    pub ban_level: u32,
    /// Rate (req/window) associated with the triggering burst (see
    /// [`DetectorVerdict::HardBurst::rps`](super::super::detector::DetectorVerdict)).
    pub last_rps: u32,
    /// Detector reason that fired the ban (e.g. `burst`, `fp_burst`).
    pub reason: String,
}

/// Point-in-time snapshot row of a single live ban, for the admin API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BanSnapshot {
    pub ip: IpAddr,
    pub expires_ms: i64,
    pub ban_level: u32,
    pub last_rps: u32,
    pub reason: String,
}

/// TTL-aware IP ban table for dynamic `DDoS` bans.
///
/// Separate from `access::IpCidrTable` which is immutable after config load.
/// This table supports per-entry TTL with automatic expiry checks.
pub struct DynamicBanTable {
    /// IP → ban state (expiry + metadata).
    entries: DashMap<IpAddr, BanState>,
}

impl DynamicBanTable {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    /// Insert or extend a ban with expiry only (metadata defaulted).
    ///
    /// Convenience for callers that only know the expiry (manual/test paths).
    /// Production bans go through [`Self::insert_ban`] with full metadata.
    pub fn insert(&self, ip: IpAddr, expires_ms: i64) {
        self.insert_ban(
            ip,
            BanState {
                expires_ms,
                ban_level: 0,
                last_rps: 0,
                reason: "dynamic".to_string(),
            },
        );
    }

    /// Insert or extend a ban with full metadata.
    ///
    /// On an existing entry the longer expiry wins and the latest (escalated)
    /// metadata is adopted.
    pub fn insert_ban(&self, ip: IpAddr, state: BanState) {
        self.entries
            .entry(ip)
            .and_modify(|cur| {
                if state.expires_ms >= cur.expires_ms {
                    *cur = state.clone();
                }
            })
            .or_insert(state);
    }

    /// Check if IP is currently banned.
    #[must_use]
    pub fn contains(&self, ip: IpAddr, now_ms: i64) -> bool {
        self.entries.get(&ip).is_some_and(|s| s.expires_ms > now_ms)
    }

    /// Remove a single ban. Returns `true` if an entry was present.
    pub fn remove(&self, ip: IpAddr) -> bool {
        self.entries.remove(&ip).is_some()
    }

    /// Snapshot all non-expired bans as of `now_ms`.
    #[must_use]
    pub fn snapshot(&self, now_ms: i64) -> Vec<BanSnapshot> {
        self.entries
            .iter()
            .filter(|e| e.value().expires_ms > now_ms)
            .map(|e| BanSnapshot {
                ip: *e.key(),
                expires_ms: e.value().expires_ms,
                ban_level: e.value().ban_level,
                last_rps: e.value().last_rps,
                reason: e.value().reason.clone(),
            })
            .collect()
    }

    /// Remove expired entries. Returns count purged.
    pub fn purge_expired(&self, now_ms: i64) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, s| s.expires_ms > now_ms);
        before.saturating_sub(self.entries.len())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&self) {
        self.entries.clear();
    }
}

impl Default for DynamicBanTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Single step in the ban escalation schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BanStep {
    /// Ban duration in seconds.
    pub ttl_s: u32,
    /// Risk delta to apply.
    pub risk_delta: u8,
}

/// Configurable ban escalation schedule.
///
/// Default: 60s→5m→1h with risk 30→50→100.
#[derive(Clone, Debug)]
pub struct BanSchedule {
    steps: Vec<BanStep>,
}

impl BanSchedule {
    /// Create a schedule from steps. Must have at least one step.
    ///
    /// # Panics
    /// Panics if `steps` is empty.
    #[must_use]
    pub fn new(steps: Vec<BanStep>) -> Self {
        assert!(!steps.is_empty(), "BanSchedule requires at least one step");
        Self { steps }
    }

    /// Look up the ban parameters for the given offense number (1-indexed).
    ///
    /// Offense 0 is treated as 1. Offenses beyond the schedule length
    /// use the last (harshest) step.
    #[must_use]
    pub fn step_for(&self, offense_n: u64) -> BanStep {
        // Clamp offense to valid index range. Steps is guaranteed non-empty by constructor.
        let max_idx = self.steps.len().saturating_sub(1);
        let idx = usize::try_from(offense_n.saturating_sub(1))
            .unwrap_or(max_idx)
            .min(max_idx);
        // steps is non-empty (asserted in constructor), so first() always succeeds
        self.steps
            .get(idx)
            .or_else(|| self.steps.first())
            .copied()
            .unwrap_or(BanStep {
                ttl_s: 3600,
                risk_delta: 100,
            })
    }
}

impl Default for BanSchedule {
    /// Default escalation: 60s/+30 → 5m/+50 → 1h/+100
    fn default() -> Self {
        Self::new(vec![
            BanStep {
                ttl_s: 60,
                risk_delta: 30,
            },
            BanStep {
                ttl_s: 300,
                risk_delta: 50,
            },
            BanStep {
                ttl_s: 3600,
                risk_delta: 100,
            },
        ])
    }
}

/// Ban action executor with TTL escalation for `DDoS` violations.
pub struct BanAction {
    ban_table: Arc<DynamicBanTable>,
    offense_store: Arc<dyn CounterStore>,
    schedule: BanSchedule,
    /// Offense window in milliseconds (default: 1 hour).
    offense_window_ms: i64,
    /// Debounce window to prevent double-escalation (default: 100ms).
    debounce_ms: i64,
    /// Debounce locks: IP → last-ban timestamp
    debounce_locks: DashMap<IpAddr, i64>,
}

impl BanAction {
    /// Create a new ban action with custom schedule.
    #[must_use]
    pub fn new(ban_table: Arc<DynamicBanTable>, offense_store: Arc<dyn CounterStore>, schedule: BanSchedule) -> Self {
        Self {
            ban_table,
            offense_store,
            schedule,
            offense_window_ms: 3600 * 1000, // 1 hour
            debounce_ms: 100,
            debounce_locks: DashMap::new(),
        }
    }

    /// Create with default escalation schedule.
    #[must_use]
    pub fn with_defaults(ban_table: Arc<DynamicBanTable>, offense_store: Arc<dyn CounterStore>) -> Self {
        Self::new(ban_table, offense_store, BanSchedule::default())
    }

    /// Build the offense counter key for an IP.
    fn offense_key(ip: IpAddr) -> String {
        format!("ddos:offense:{ip}")
    }

    /// Check and update debounce lock. Returns true if this call should proceed.
    fn acquire_debounce(&self, ip: IpAddr, now_ms: i64) -> bool {
        let mut should_proceed = false;
        self.debounce_locks
            .entry(ip)
            .and_modify(|last| {
                if now_ms.saturating_sub(*last) >= self.debounce_ms {
                    *last = now_ms;
                    should_proceed = true;
                }
            })
            .or_insert_with(|| {
                should_proceed = true;
                now_ms
            });
        should_proceed
    }

    /// Periodic cleanup of stale debounce locks.
    pub fn purge_debounce_locks(&self, now_ms: i64) {
        let cutoff = now_ms.saturating_sub(self.debounce_ms * 10);
        self.debounce_locks.retain(|_, ts| *ts > cutoff);
    }
}

impl ActionExecutor for BanAction {
    fn name(&self) -> &'static str {
        "ban"
    }

    fn execute(&self, ip: IpAddr, verdict: &DetectorVerdict, now_ms: i64) -> ActionResult {
        // Only act on HardBurst verdicts
        let (reason, detector, rps) = match verdict {
            DetectorVerdict::HardBurst { reason, detector, rps } => (*reason, *detector, *rps),
            _ => return ActionResult::noop(),
        };

        // Debounce: skip if same IP was banned within 100ms
        if !self.acquire_debounce(ip, now_ms) {
            return ActionResult::noop();
        }

        // Increment offense counter
        let offense_key = Self::offense_key(ip);
        let offense_n = match self
            .offense_store
            .incr_get_blocking(&offense_key, self.offense_window_ms, now_ms)
        {
            Ok(n) => n,
            Err(e) => {
                warn!(
                    action = "ban",
                    ip = %ip,
                    error = %e,
                    "offense store error, skipping ban"
                );
                return ActionResult::noop();
            }
        };

        // Look up escalation step
        let step = self.schedule.step_for(offense_n);
        let expires_ms = now_ms.saturating_add(i64::from(step.ttl_s) * 1000);

        // Insert ban with full metadata for the admin ban table.
        self.ban_table.insert_ban(
            ip,
            BanState {
                expires_ms,
                ban_level: u32::try_from(offense_n).unwrap_or(u32::MAX),
                last_rps: rps,
                reason: reason.to_string(),
            },
        );

        // Structured audit log for ban events
        warn!(
            action = "ban",
            ip = %ip,
            offense = offense_n,
            ttl_s = step.ttl_s,
            risk_delta = step.risk_delta,
            reason = reason,
            detector = detector,
            "IP banned for DDoS violation"
        );

        ActionResult {
            banned: true,
            ban_ttl_s: Some(step.ttl_s),
            risk_delta: step.risk_delta,
        }
    }
}

/// Current wall-clock epoch milliseconds.
#[must_use]
pub fn now_epoch_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::ddos::store::MemoryCounterStore;

    fn make_ban_action() -> (Arc<DynamicBanTable>, BanAction) {
        let table = Arc::new(DynamicBanTable::new());
        let store = Arc::new(MemoryCounterStore::new(1000, 60));
        let action = BanAction::with_defaults(Arc::clone(&table), store);
        (table, action)
    }

    fn hard_burst() -> DetectorVerdict {
        DetectorVerdict::HardBurst {
            reason: "burst",
            detector: "per_ip",
            rps: 123,
        }
    }

    #[test]
    fn dynamic_ban_table_insert_and_contains() {
        let table = DynamicBanTable::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        assert!(!table.contains(ip, 1000));
        table.insert(ip, 5000);
        assert!(table.contains(ip, 1000));
        assert!(table.contains(ip, 4999));
        assert!(!table.contains(ip, 5000)); // expired at exact boundary
        assert!(!table.contains(ip, 6000));
    }

    #[test]
    fn dynamic_ban_table_extends_existing() {
        let table = DynamicBanTable::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        table.insert(ip, 1000);
        table.insert(ip, 2000); // extend
        assert!(table.contains(ip, 1500));
    }

    #[test]
    fn dynamic_ban_table_purge() {
        let table = DynamicBanTable::new();
        table.insert("1.1.1.1".parse().unwrap(), 1000);
        table.insert("2.2.2.2".parse().unwrap(), 3000);
        assert_eq!(table.len(), 2);

        let purged = table.purge_expired(2000);
        assert_eq!(purged, 1);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn dynamic_ban_table_remove() {
        let table = DynamicBanTable::new();
        let ip: IpAddr = "9.9.9.9".parse().unwrap();
        table.insert(ip, 5000);
        assert!(table.remove(ip), "present entry removed");
        assert!(!table.remove(ip), "absent entry returns false (idempotent)");
        assert!(!table.contains(ip, 1000));
    }

    #[test]
    fn dynamic_ban_table_snapshot_excludes_expired() {
        let table = DynamicBanTable::new();
        table.insert("1.1.1.1".parse().unwrap(), 5000);
        table.insert("2.2.2.2".parse().unwrap(), 1500);
        // now=2000 → only 1.1.1.1 (expires 5000) is live.
        let rows = table.snapshot(2000);
        assert_eq!(rows.len(), 1);
        let row = rows.first().unwrap();
        assert_eq!(row.ip, "1.1.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(row.expires_ms, 5000);
    }

    #[test]
    fn ban_action_records_level_rps_reason() {
        let (table, action) = make_ban_action();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let r = action.execute(ip, &hard_burst(), 1000);
        assert!(r.banned);
        let rows = table.snapshot(1000);
        assert_eq!(rows.len(), 1);
        let row = rows.first().unwrap();
        assert_eq!(row.ban_level, 1, "first offense → level 1");
        assert_eq!(row.last_rps, 123, "rps carried from verdict");
        assert_eq!(row.reason, "burst");
    }

    #[test]
    fn ban_schedule_default() {
        let schedule = BanSchedule::default();
        assert_eq!(
            schedule.step_for(1),
            BanStep {
                ttl_s: 60,
                risk_delta: 30
            }
        );
        assert_eq!(
            schedule.step_for(2),
            BanStep {
                ttl_s: 300,
                risk_delta: 50
            }
        );
        assert_eq!(
            schedule.step_for(3),
            BanStep {
                ttl_s: 3600,
                risk_delta: 100
            }
        );
        assert_eq!(
            schedule.step_for(4),
            BanStep {
                ttl_s: 3600,
                risk_delta: 100
            }
        );
        assert_eq!(
            schedule.step_for(100),
            BanStep {
                ttl_s: 3600,
                risk_delta: 100
            }
        );
    }

    #[test]
    fn ban_schedule_offense_zero_treated_as_one() {
        let schedule = BanSchedule::default();
        assert_eq!(
            schedule.step_for(0),
            BanStep {
                ttl_s: 60,
                risk_delta: 30
            }
        );
    }

    #[test]
    fn ban_action_ignores_allow_verdict() {
        let (_table, action) = make_ban_action();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let result = action.execute(ip, &DetectorVerdict::Allow, 1000);
        assert_eq!(result, ActionResult::noop());
    }

    #[test]
    fn ban_action_ignores_soft_anomaly() {
        let (_table, action) = make_ban_action();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let result = action.execute(ip, &DetectorVerdict::SoftAnomaly(50), 1000);
        assert_eq!(result, ActionResult::noop());
    }

    #[test]
    fn ban_action_first_offense() {
        let (table, action) = make_ban_action();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        let result = action.execute(ip, &hard_burst(), 1000);
        assert!(result.banned);
        assert_eq!(result.ban_ttl_s, Some(60));
        assert_eq!(result.risk_delta, 30);
        assert!(table.contains(ip, 1000));
    }

    #[test]
    fn ban_action_escalates_on_repeat() {
        let (_table, action) = make_ban_action();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // 1st offense
        let r1 = action.execute(ip, &hard_burst(), 1000);
        assert_eq!(r1.ban_ttl_s, Some(60));

        // 2nd offense (after debounce)
        let r2 = action.execute(ip, &hard_burst(), 2000);
        assert_eq!(r2.ban_ttl_s, Some(300));

        // 3rd offense
        let r3 = action.execute(ip, &hard_burst(), 3000);
        assert_eq!(r3.ban_ttl_s, Some(3600));

        // 4th offense (capped at 3rd)
        let r4 = action.execute(ip, &hard_burst(), 4000);
        assert_eq!(r4.ban_ttl_s, Some(3600));
    }

    #[test]
    fn ban_action_debounce_prevents_double_escalation() {
        let (_, action) = make_ban_action();
        let ip: IpAddr = "172.16.0.1".parse().unwrap();

        // First ban
        let r1 = action.execute(ip, &hard_burst(), 1000);
        assert!(r1.banned);

        // Within debounce window (50ms later) - should be skipped
        let r2 = action.execute(ip, &hard_burst(), 1050);
        assert_eq!(r2, ActionResult::noop());

        // After debounce window (150ms later) - should proceed
        let r3 = action.execute(ip, &hard_burst(), 1150);
        assert!(r3.banned);
        assert_eq!(r3.ban_ttl_s, Some(300)); // escalated to 2nd
    }

    #[test]
    fn ban_action_different_ips_independent() {
        let (_, action) = make_ban_action();
        let ip1: IpAddr = "1.1.1.1".parse().unwrap();
        let ip2: IpAddr = "2.2.2.2".parse().unwrap();

        let r1 = action.execute(ip1, &hard_burst(), 1000);
        let r2 = action.execute(ip2, &hard_burst(), 1000);

        // Both should be 1st offense
        assert_eq!(r1.ban_ttl_s, Some(60));
        assert_eq!(r2.ban_ttl_s, Some(60));
    }
}
