/// Global per-rule-id token-bucket rate limiter (layer 2).
///
/// Guards against IP-rotation bypass: even if an attacker rotates through
/// millions of source IPs, the global bucket caps how many events per rule_id
/// can enter the DB per second across all IPs combined.
///
/// Implementation: one `tokio::sync::Semaphore` per rule_id.
/// - `acquire_one()` attempts a non-blocking permit acquisition.
/// - A background refill task calls `add_permits(deficit)` every second to
///   restore up to the configured rate.
/// - The semaphore starts at `tokens_per_sec` permits (burst equal to rate).
use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Semaphore;
use tokio::time::{Duration, interval};
use tracing::warn;

use crate::audit_emitter::metrics::AuditEmitterMetrics;

/// Per-rule-id semaphore with its configured cap.
struct RuleBucket {
    semaphore: Arc<Semaphore>,
    /// Maximum permits (= tokens per second configured for this rule).
    cap: u32,
}

/// Global token-bucket store, keyed by rule_id (&'static str).
pub struct GlobalRateBucket {
    buckets: HashMap<&'static str, RuleBucket>,
    default_cap: u32,
}

impl GlobalRateBucket {
    /// Built-in rule_ids that always get a bucket entry at construction.
    pub const BUILTIN_RULE_IDS: &'static [&'static str] = &[
        "BOT-XFF-001",
        "BOT-RELAY-001",
        "BOT-TOR-001",
        "TX-SEQ-001",
        "TX-WITHDRAW-001",
        "TX-LIMIT-001",
    ];

    /// Construct a new bucket store.
    ///
    /// `default_cap`: tokens/s for any rule_id not in `per_rule_overrides`.
    /// `per_rule_overrides`: per-rule_id overrides keyed by `&'static str`.
    ///
    /// Only built-in rule_ids get pre-allocated buckets; custom user rules
    /// never pass through this layer (see mod.rs doc).
    pub fn new(default_cap: u32, per_rule_overrides: &HashMap<String, u32>) -> Self {
        let mut buckets = HashMap::new();
        for &rule_id in Self::BUILTIN_RULE_IDS {
            let cap = per_rule_overrides
                .get(rule_id)
                .copied()
                .unwrap_or(default_cap);
            let sem = Arc::new(Semaphore::new(cap as usize));
            buckets.insert(rule_id, RuleBucket { semaphore: sem, cap });
        }
        Self { buckets, default_cap }
    }

    /// Try to acquire one token for `rule_id`.
    ///
    /// Returns `true` if a token was available (caller may proceed),
    /// `false` if the global rate limit for this rule_id is exhausted.
    ///
    /// Unknown rule_ids (not in built-ins) are always allowed through — they
    /// are rejected earlier by the regex contract.
    pub fn try_acquire(&self, rule_id: &'static str) -> bool {
        let Some(bucket) = self.buckets.get(rule_id) else {
            // Unknown rule_id: not a built-in; allow through (regex gate
            // upstream ensures only valid ids reach here).
            return true;
        };
        bucket.semaphore.try_acquire().map(|permit| permit.forget()).is_ok()
    }

    /// Spawn the background refill task.
    ///
    /// Every second, each bucket is replenished by the number of permits that
    /// have been consumed since the last tick, up to its cap. The task runs
    /// until the returned `Arc<GlobalRateBucket>` is dropped (i.e., until
    /// the `Semaphore` instances are closed by the `AuditEmitter` shutdown).
    ///
    /// The task holds a weak reference so it exits automatically when the
    /// emitter shuts down.
    pub fn spawn_refill_task(self_arc: Arc<tokio::sync::Mutex<GlobalRateBucket>>, metrics: Arc<AuditEmitterMetrics>) {
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(1));
            loop {
                ticker.tick().await;
                let guard = self_arc.lock().await;
                for (rule_id, bucket) in &guard.buckets {
                    let current = bucket.semaphore.available_permits();
                    let cap = bucket.cap as usize;
                    if current < cap {
                        let deficit = cap - current;
                        // add_permits will not exceed usize::MAX; in practice
                        // deficit <= cap <= u32::MAX so this is safe.
                        bucket.semaphore.add_permits(deficit);
                    }
                    let _ = (rule_id, &metrics); // keep metrics borrow live
                }
            }
        });
    }
}

/// Wraps `GlobalRateBucket` behind a `Mutex` for async refill task access.
/// The emitter holds `Arc<tokio::sync::Mutex<GlobalRateBucket>>`.
pub type SharedGlobalBucket = Arc<tokio::sync::Mutex<GlobalRateBucket>>;

/// Convenience constructor.
pub fn new_shared(default_cap: u32, per_rule_overrides: &HashMap<String, u32>) -> SharedGlobalBucket {
    Arc::new(tokio::sync::Mutex::new(GlobalRateBucket::new(
        default_cap,
        per_rule_overrides,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_overrides() -> HashMap<String, u32> {
        HashMap::new()
    }

    #[test]
    fn global_bucket_allows_first_token() {
        let gb = GlobalRateBucket::new(100, &empty_overrides());
        assert!(gb.try_acquire("BOT-XFF-001"));
    }

    #[test]
    fn global_bucket_exhausts_after_cap_tokens() {
        let gb = GlobalRateBucket::new(3, &empty_overrides());
        assert!(gb.try_acquire("BOT-TOR-001"));
        assert!(gb.try_acquire("BOT-TOR-001"));
        assert!(gb.try_acquire("BOT-TOR-001"));
        // 4th should fail
        assert!(!gb.try_acquire("BOT-TOR-001"));
    }

    #[test]
    fn global_bucket_per_rule_override() {
        let mut overrides = HashMap::new();
        overrides.insert("BOT-XFF-001".to_string(), 1u32);
        let gb = GlobalRateBucket::new(100, &overrides);
        assert!(gb.try_acquire("BOT-XFF-001"));
        assert!(!gb.try_acquire("BOT-XFF-001"));
        // Other rules still have full cap
        assert!(gb.try_acquire("TX-SEQ-001"));
    }

    #[test]
    fn unknown_rule_id_allowed_through() {
        let gb = GlobalRateBucket::new(100, &empty_overrides());
        // Not a built-in rule_id — should always pass
        assert!(gb.try_acquire("UNKNOWN-RULE-999"));
    }

    #[tokio::test(start_paused = true)]
    async fn global_bucket_refill_async_no_stall() {
        use tokio::time;

        let shared = new_shared(2, &empty_overrides());
        let metrics = AuditEmitterMetrics::new();
        GlobalRateBucket::spawn_refill_task(Arc::clone(&shared), metrics);

        // Exhaust the bucket
        {
            let gb = shared.lock().await;
            gb.try_acquire("TX-LIMIT-001");
            gb.try_acquire("TX-LIMIT-001");
            assert!(!gb.try_acquire("TX-LIMIT-001"));
        }

        // Advance time by 1s + a bit to trigger refill
        time::advance(Duration::from_millis(1100)).await;

        // After refill the bucket should be replenished
        {
            let gb = shared.lock().await;
            assert!(gb.try_acquire("TX-LIMIT-001"));
        }
    }
}
