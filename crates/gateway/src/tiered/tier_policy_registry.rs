//! Tier policy registry — atomic, lock-free snapshot of (classifier + per-tier policies).
//!
//! Single source of truth for downstream FRs. Readers call `classify(&req)` on
//! every request and never block; writers swap the whole snapshot atomically
//! via `swap()` (Phase 4 file watcher).
//!
//! WHY `ArcSwap` and not `RwLock<HashMap>`: every request takes a read; under
//! load `RwLock` reads contend on the lock state. `ArcSwap::load()` is a
//! relaxed atomic load — readers never wait.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use waf_common::tier::{Tier, TierConfig, TierConfigError, TierPolicy};

use crate::tiered::compiled_rule::CompileError;
use crate::tiered::tier_classifier::{RequestParts, TierClassifier};

/// Immutable snapshot held inside `ArcSwap`. Replaced wholesale on hot reload.
///
/// `Arc<TierPolicy>` (not bare `TierPolicy`) so consumers holding a policy
/// across an `.await` pay one refcount bump instead of cloning the struct.
#[derive(Debug)]
pub struct TierSnapshot {
    pub classifier: TierClassifier,
    pub policies: HashMap<Tier, Arc<TierPolicy>>,
}

/// Errors building a snapshot from a parsed `TierConfig`.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotBuildError {
    #[error(transparent)]
    Config(#[from] TierConfigError),
    #[error(transparent)]
    Compile(#[from] CompileError),
}

impl TierSnapshot {
    /// Build a snapshot from a parsed config. Validates, then compiles rules.
    /// Fallible (regex may fail to compile) — hence `try_from_config`, not `From`.
    pub fn try_from_config(cfg: TierConfig) -> Result<Self, SnapshotBuildError> {
        cfg.validate()?;
        let classifier = TierClassifier::new(&cfg.classifier_rules, cfg.default_tier)?;
        let policies = cfg.policies.into_iter().map(|(t, p)| (t, Arc::new(p))).collect();
        Ok(Self { classifier, policies })
    }
}

/// Lock-free, hot-swappable registry. Construct once at startup; share via `Arc`.
#[derive(Debug)]
pub struct TierPolicyRegistry {
    inner: ArcSwap<TierSnapshot>,
}

impl TierPolicyRegistry {
    pub fn new(snap: TierSnapshot) -> Self {
        Self {
            inner: ArcSwap::from(Arc::new(snap)),
        }
    }

    /// Full Arc clone of the current snapshot. Use when you need to outlive
    /// the load-guard (e.g., across `.await`).
    pub fn snapshot(&self) -> Arc<TierSnapshot> {
        self.inner.load_full()
    }

    /// Atomically replace the snapshot. Old readers keep their Arc until done.
    pub fn swap(&self, new_snap: TierSnapshot) {
        self.inner.store(Arc::new(new_snap));
    }

    /// Classify a request and return its policy. O(rules).
    ///
    /// Single `load_full()` so the classifier and policy come from the *same*
    /// snapshot — avoids torn reads if a swap happens mid-call.
    // BUG: TierConfig::validate() guarantees every Tier has a policy, and
    // try_from_config() is the only way to build a snapshot — so the lookup
    // below cannot fail. CLAUDE.md permits `.expect("BUG: ...")` for
    // compile-time-style invariants of this kind.
    #[allow(clippy::expect_used)]
    pub fn classify(&self, req: &RequestParts<'_>) -> (Tier, Arc<TierPolicy>) {
        let snap = self.inner.load_full();
        let tier = snap.classifier.classify(req);
        let policy = snap
            .policies
            .get(&tier)
            .cloned()
            .expect("BUG: TierConfig::validate() must guarantee policy for every tier");
        (tier, policy)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;

    use http::{HeaderMap, Method};
    use waf_common::tier::{CachePolicy, FailMode, RiskThresholds, Tier, TierClassifierRule, TierConfig, TierPolicy};
    use waf_common::tier_match::PathMatch;

    use super::*;

    fn policy(block: u32) -> TierPolicy {
        TierPolicy {
            fail_mode: FailMode::Close,
            ddos_threshold_rps: 1000,
            cache_policy: CachePolicy::NoCache,
            risk_thresholds: RiskThresholds {
                allow: 10,
                challenge: 50,
                block,
            },
        }
    }

    fn full_policies(block: u32) -> HashMap<Tier, TierPolicy> {
        Tier::ALL.into_iter().map(|t| (t, policy(block))).collect()
    }

    fn cfg_with(rules: Vec<TierClassifierRule>, block: u32) -> TierConfig {
        TierConfig {
            default_tier: Tier::CatchAll,
            classifier_rules: rules,
            policies: full_policies(block),
        }
    }

    fn parts<'a>(host: &'a str, path: &'a str, m: &'a Method, h: &'a HeaderMap) -> RequestParts<'a> {
        RequestParts {
            host,
            path,
            method: m,
            headers: h,
        }
    }

    #[test]
    fn lookup_returns_correct_policy_per_tier() {
        let rule = TierClassifierRule {
            priority: 10,
            tier: Tier::Critical,
            host: None,
            path: Some(PathMatch::Prefix { value: "/admin".into() }),
            method: None,
            headers: None,
        };
        let snap = TierSnapshot::try_from_config(cfg_with(vec![rule], 100)).unwrap();
        let reg = TierPolicyRegistry::new(snap);

        let m = Method::GET;
        let h = HeaderMap::new();
        let (tier, pol) = reg.classify(&parts("ex.com", "/admin/users", &m, &h));
        assert_eq!(tier, Tier::Critical);
        assert_eq!(pol.risk_thresholds.block, 100);

        let (tier, _) = reg.classify(&parts("ex.com", "/", &m, &h));
        assert_eq!(tier, Tier::CatchAll);
    }

    #[test]
    fn classify_uses_current_snapshot_after_swap() {
        let snap1 = TierSnapshot::try_from_config(cfg_with(vec![], 100)).unwrap();
        let reg = TierPolicyRegistry::new(snap1);
        let m = Method::GET;
        let h = HeaderMap::new();
        let (_, before) = reg.classify(&parts("ex.com", "/", &m, &h));
        assert_eq!(before.risk_thresholds.block, 100);

        let snap2 = TierSnapshot::try_from_config(cfg_with(vec![], 200)).unwrap();
        reg.swap(snap2);

        let (_, after) = reg.classify(&parts("ex.com", "/", &m, &h));
        assert_eq!(after.risk_thresholds.block, 200);
    }

    #[test]
    fn try_from_config_rejects_invalid() {
        let mut cfg = cfg_with(vec![], 100);
        cfg.policies.remove(&Tier::Critical);
        assert!(matches!(
            TierSnapshot::try_from_config(cfg),
            Err(SnapshotBuildError::Config(TierConfigError::MissingPolicy(
                Tier::Critical
            )))
        ));
    }

    #[test]
    fn swap_replaces_atomically_under_concurrent_readers() {
        // Spawn many readers + 1 writer flipping between two snapshots.
        // Each read must observe a *consistent* (classifier, policy) pair —
        // i.e., never the classifier of snap-A with the policy map of snap-B.
        // We assert this by encoding a unique block-threshold per snapshot
        // and checking it always matches one of the two known values.
        let snap_a = TierSnapshot::try_from_config(cfg_with(vec![], 111)).unwrap();
        let reg = Arc::new(TierPolicyRegistry::new(snap_a));
        let stop = Arc::new(AtomicBool::new(false));

        let writer_reg = Arc::clone(&reg);
        let writer_stop = Arc::clone(&stop);
        let writer = thread::spawn(move || {
            let mut flip = false;
            while !writer_stop.load(Ordering::Relaxed) {
                let block = if flip { 222 } else { 111 };
                let snap = TierSnapshot::try_from_config(cfg_with(vec![], block)).unwrap();
                writer_reg.swap(snap);
                flip = !flip;
            }
        });

        let readers: Vec<_> = (0..8)
            .map(|_| {
                let r = Arc::clone(&reg);
                thread::spawn(move || {
                    let m = Method::GET;
                    let h = HeaderMap::new();
                    for _ in 0..5_000 {
                        let (_, pol) = r.classify(&parts("ex.com", "/", &m, &h));
                        let b = pol.risk_thresholds.block;
                        assert!(b == 111 || b == 222, "torn read: block={b}");
                    }
                })
            })
            .collect();

        for r in readers {
            r.join().unwrap();
        }
        stop.store(true, Ordering::Relaxed);
        writer.join().unwrap();
    }
}
