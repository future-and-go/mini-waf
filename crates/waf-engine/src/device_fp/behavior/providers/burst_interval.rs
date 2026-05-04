//! FR-RS-048 — burst-interval classifier.
//!
//! Fires when the tail of the actor's sample window contains
//! `min_consecutive` (default 5) consecutive inter-request intervals each
//! strictly less than `threshold_ms` (default 50). Strict `<` is
//! deliberate: an interval of exactly the threshold is a boundary case
//! that operators tune via config, not via this comparator.
//!
//! Pure over an `ActorBehaviorSnapshot` — zero allocations, no I/O.
//! Snapshot acquisition (`Recorder::snapshot`) clones the bounded ring out
//! of the `DashMap` shard so we never hold a shard guard across evaluation.

use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::device_fp::behavior::recorder::Recorder;
use crate::device_fp::config::DeviceFpConfig;
use crate::device_fp::providers::SignalProvider;
use crate::device_fp::signal::Signal;
use crate::device_fp::types::DeviceCtx;

pub struct BurstIntervalProvider {
    recorder: Arc<Recorder>,
    cfg: Arc<ArcSwap<DeviceFpConfig>>,
}

impl BurstIntervalProvider {
    #[must_use]
    pub const fn new(recorder: Arc<Recorder>, cfg: Arc<ArcSwap<DeviceFpConfig>>) -> Self {
        Self { recorder, cfg }
    }
}

impl SignalProvider for BurstIntervalProvider {
    fn name(&self) -> &'static str {
        "burst_interval"
    }

    fn evaluate(&self, ctx: &DeviceCtx<'_>) -> Vec<Signal> {
        // Per-call load — never cache the Guard. Hot-reload swaps the
        // Arc atomically; caching would pin a stale revision.
        let cfg = self.cfg.load();
        let bi = &cfg.behavior.burst_interval;
        if !bi.enabled {
            return Vec::new();
        }

        let Some(snap) = self.recorder.snapshot(ctx.key) else {
            return Vec::new();
        };

        // N samples → N-1 intervals. With <2 samples there is no interval
        // to classify, so silence is the only correct answer.
        if snap.samples.len() < 2 {
            return Vec::new();
        }

        // Count the trailing run of sub-threshold intervals. We iterate
        // from newest pair backwards because a burst is a *tail* property:
        // a single slow interval at the end breaks the run regardless of
        // anything older.
        // Slice-pattern match avoids the `clippy::indexing_slicing` lint.
        // `windows(2)` always yields 2-element slices; the `_` arm is dead.
        let run = snap
            .samples
            .windows(2)
            .rev()
            .filter_map(|pair| match pair {
                [a, b] => Some(b.ts_ms.saturating_sub(a.ts_ms)),
                _ => None,
            })
            .take_while(|&d| d < bi.threshold_ms)
            .count();

        if run >= usize::from(bi.min_consecutive) {
            // u16 is safe: WINDOW=16 caps `run` at 15; far below u16::MAX.
            #[allow(clippy::cast_possible_truncation)]
            let count = run as u16;
            vec![Signal::BurstInterval { count }]
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_fp::behavior::config::{BehaviorConfig, BurstIntervalCfg};
    use crate::device_fp::capture::ConnCtx;
    use crate::device_fp::types::{FingerprintValue, FpKey};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;
    use waf_common::tier::Tier;

    fn cfg_default() -> Arc<ArcSwap<DeviceFpConfig>> {
        Arc::new(ArcSwap::from_pointee(DeviceFpConfig::default()))
    }

    fn key(tag: &str) -> FpKey {
        FpKey {
            ja3: Some(FingerprintValue::new(tag)),
            ja4: None,
            h2_akamai: None,
        }
    }

    /// Drive the recorder with `n` records spaced by `interval_ms` of real
    /// monotonic time. Slow but deterministic for the boundary cases the
    /// plan calls out (off-by-one, strict-less-than).
    fn record_n_with_interval(rec: &Arc<Recorder>, k: &FpKey, n: usize, interval_ms: u64) {
        for i in 0..n {
            rec.record(k, "/p", false, false, Tier::CatchAll);
            // Skip the trailing sleep — it would only delay the test.
            if i + 1 < n {
                std::thread::sleep(Duration::from_millis(interval_ms));
            }
        }
    }

    fn eval(p: &BurstIntervalProvider, k: &FpKey) -> Vec<Signal> {
        let conn = ConnCtx::new();
        let ctx = DeviceCtx::new(IpAddr::V4(Ipv4Addr::LOCALHOST), "ua", &conn, k);
        p.evaluate(&ctx)
    }

    #[test]
    fn fires_on_six_samples_at_thirty_ms() {
        // 6 samples at 30 ms intervals → 5 intervals all < 50 ms → fires.
        let cfg = cfg_default();
        let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
        let k = key("a");
        record_n_with_interval(&rec, &k, 6, 30);
        let p = BurstIntervalProvider::new(Arc::clone(&rec), cfg);
        let signals = eval(&p, &k);
        assert_eq!(signals.len(), 1);
        match signals.first() {
            Some(Signal::BurstInterval { count }) => {
                assert!(*count >= 5, "expected ≥5, got {count}");
            }
            other => panic!("wrong signal: {other:?}"),
        }
    }

    #[test]
    fn silent_below_min_consecutive() {
        // 4 samples at 30 ms → only 3 intervals → below min_consecutive=5.
        let cfg = cfg_default();
        let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
        let k = key("b");
        record_n_with_interval(&rec, &k, 4, 30);
        let p = BurstIntervalProvider::new(Arc::clone(&rec), cfg);
        assert!(eval(&p, &k).is_empty());
    }

    #[test]
    fn run_broken_by_slow_interval_in_middle() {
        // Pattern [30, 30, 200, 30, 30, 30] — tail run is only 3 intervals
        // (the three trailing 30 ms gaps), broken by the 200 ms gap.
        // Build via direct snapshot manipulation would mean exposing
        // internals; instead, drive recorder with a real 200 ms sleep.
        let cfg = cfg_default();
        let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
        let k = key("c");

        // First three samples 30 ms apart.
        rec.record(&k, "/p", false, false, Tier::CatchAll);
        std::thread::sleep(Duration::from_millis(30));
        rec.record(&k, "/p", false, false, Tier::CatchAll);
        std::thread::sleep(Duration::from_millis(30));
        rec.record(&k, "/p", false, false, Tier::CatchAll);
        // The break.
        std::thread::sleep(Duration::from_millis(200));
        rec.record(&k, "/p", false, false, Tier::CatchAll);
        std::thread::sleep(Duration::from_millis(30));
        rec.record(&k, "/p", false, false, Tier::CatchAll);
        std::thread::sleep(Duration::from_millis(30));
        rec.record(&k, "/p", false, false, Tier::CatchAll);

        let p = BurstIntervalProvider::new(Arc::clone(&rec), cfg);
        // Tail run = 3 (< min=5) → silent.
        assert!(eval(&p, &k).is_empty());
    }

    #[test]
    fn silent_when_no_actor_recorded() {
        // Provider must not panic / fire when snapshot is None.
        let cfg = cfg_default();
        let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
        let p = BurstIntervalProvider::new(Arc::clone(&rec), cfg);
        assert!(eval(&p, &key("never-seen")).is_empty());
    }

    #[test]
    fn silent_with_single_sample() {
        // 1 sample → 0 intervals → silent regardless of config.
        let cfg = cfg_default();
        let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
        let k = key("e");
        rec.record(&k, "/p", false, false, Tier::CatchAll);
        let p = BurstIntervalProvider::new(Arc::clone(&rec), cfg);
        assert!(eval(&p, &k).is_empty());
    }

    #[test]
    fn silent_when_disabled() {
        // Even with a clear burst pattern, `enabled: false` must suppress.
        let cfg = Arc::new(ArcSwap::from_pointee(DeviceFpConfig {
            behavior: BehaviorConfig {
                burst_interval: BurstIntervalCfg {
                    enabled: false,
                    ..BurstIntervalCfg::default()
                },
                ..BehaviorConfig::default()
            },
            ..DeviceFpConfig::default()
        }));
        let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
        let k = key("f");
        record_n_with_interval(&rec, &k, 6, 30);
        let p = BurstIntervalProvider::new(Arc::clone(&rec), cfg);
        assert!(eval(&p, &k).is_empty());
    }
}
