//! FR-011 — regularity (CV-based bot cadence) classifier.
//!
//! Bots that pace themselves at a fixed wall-clock interval (e.g. one
//! request per second) sit *above* the burst threshold but produce
//! intervals that are dead-uniform. We measure that uniformity via the
//! coefficient of variation (stddev / mean) over the trailing
//! `min_samples` intervals.
//!
//! `f32` is intentional — the alternative (integer-scaled stddev) needs
//! an integer sqrt and a divisor scaling dance for ~no observable benefit
//! at this sample size. Mean-zero is short-circuited before the divide.

use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::device_fp::behavior::recorder::Recorder;
use crate::device_fp::config::DeviceFpConfig;
use crate::device_fp::providers::SignalProvider;
use crate::device_fp::signal::Signal;
use crate::device_fp::types::DeviceCtx;

pub struct RegularityProvider {
    recorder: Arc<Recorder>,
    cfg: Arc<ArcSwap<DeviceFpConfig>>,
}

impl RegularityProvider {
    #[must_use]
    pub const fn new(recorder: Arc<Recorder>, cfg: Arc<ArcSwap<DeviceFpConfig>>) -> Self {
        Self { recorder, cfg }
    }
}

impl SignalProvider for RegularityProvider {
    fn name(&self) -> &'static str {
        "regularity"
    }

    // Float casts here are bounded: ring caps `n` at WINDOW=16 (well under
    // f32 mantissa precision) and intervals are millisecond gaps the
    // recorder produces — also far inside f32 range. The lint flags are
    // worst-case warnings that don't apply to our domain.
    #[allow(clippy::cast_precision_loss)]
    fn evaluate(&self, ctx: &DeviceCtx<'_>) -> Vec<Signal> {
        let cfg = self.cfg.load();
        let r = &cfg.behavior.regularity;
        if !r.enabled {
            return Vec::new();
        }

        let Some(snap) = self.recorder.snapshot(ctx.key) else {
            return Vec::new();
        };

        // N samples → N-1 intervals. We need at least `min_samples` of
        // those to evaluate cadence at all (plan: default 6).
        let min = usize::from(r.min_samples);
        if snap.samples.len() < min + 1 {
            return Vec::new();
        }

        // Tail-only window: take the most recent `min` intervals (skip the
        // older surplus). Keeps the signal locally responsive — a slow
        // morning followed by a tight spam burst should still trip it.
        let intervals: Vec<u64> = snap
            .samples
            .windows(2)
            .filter_map(|pair| match pair {
                [a, b] => Some(b.ts_ms.saturating_sub(a.ts_ms)),
                _ => None,
            })
            .collect();
        let take_from = intervals.len().saturating_sub(min);
        let tail = intervals.get(take_from..).unwrap_or(&[]);
        if tail.len() < min {
            return Vec::new();
        }

        let n = tail.len() as f32;
        let sum: f32 = tail.iter().map(|&v| v as f32).sum();
        let mean = sum / n;
        // Sub-burst-threshold cadence is owned by `burst_interval`, not us —
        // suppress here to avoid double-counting.
        if mean < r.min_mean_ms as f32 {
            return Vec::new();
        }

        let var: f32 = tail
            .iter()
            .map(|&v| {
                let d = v as f32 - mean;
                d * d
            })
            .sum::<f32>()
            / n;
        let stddev = var.sqrt();
        let cv = stddev / mean;
        // NaN-safe: any non-finite CV silences the classifier rather than
        // spuriously firing.
        if !cv.is_finite() || cv < 0.0 {
            return Vec::new();
        }
        if cv >= r.cv_threshold {
            return Vec::new();
        }

        // Wire format stays as ×1000 integer for downstream compactness.
        // cv is < cv_threshold ≤ 1.0 here, so ×1000 fits comfortably in u16.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let cv_u16 = ((cv * 1000.0).round() as u32).min(u32::from(u16::MAX)) as u16;
        vec![Signal::Regularity { cv_x1000: cv_u16 }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_fp::behavior::config::{BehaviorConfig, RegularityCfg};
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

    fn record_n(rec: &Arc<Recorder>, k: &FpKey, n: usize, interval_ms: u64) {
        for i in 0..n {
            rec.record(k, "/p", false, false, Tier::CatchAll);
            if i + 1 < n {
                std::thread::sleep(Duration::from_millis(interval_ms));
            }
        }
    }

    fn eval(p: &RegularityProvider, k: &FpKey) -> Vec<Signal> {
        let conn = ConnCtx::new();
        let ctx = DeviceCtx::new(IpAddr::V4(Ipv4Addr::LOCALHOST), "ua", &conn, k);
        p.evaluate(&ctx)
    }

    #[test]
    fn fires_on_uniform_cadence_above_burst_threshold() {
        // 7 samples spaced 200 ms apart → 6 intervals, near-zero CV, mean
        // well above the 100 ms `min_mean_ms` floor → fires.
        let cfg = cfg_default();
        let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
        let k = key("uniform");
        record_n(&rec, &k, 7, 200);
        let p = RegularityProvider::new(Arc::clone(&rec), cfg);
        let signals = eval(&p, &k);
        assert_eq!(signals.len(), 1, "expected 1 signal, got {signals:?}");
        match signals.first() {
            Some(Signal::Regularity { cv_x1000 }) => {
                assert!(*cv_x1000 < 150, "cv {cv_x1000} should be under 150");
            }
            other => panic!("wrong signal: {other:?}"),
        }
    }

    #[test]
    fn silent_on_jittery_cadence() {
        // Drive intervals 200, 30, 400, 50, 600, 80 — large CV → silent.
        let cfg = cfg_default();
        let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
        let k = key("jitter");
        let intervals = [200u64, 30, 400, 50, 600, 80];
        rec.record(&k, "/p", false, false, Tier::CatchAll);
        for d in intervals {
            std::thread::sleep(Duration::from_millis(d));
            rec.record(&k, "/p", false, false, Tier::CatchAll);
        }
        let p = RegularityProvider::new(Arc::clone(&rec), cfg);
        assert!(eval(&p, &k).is_empty());
    }

    #[test]
    fn silent_when_mean_below_floor() {
        // Uniform cadence at 30 ms → mean far below 100 ms → silent
        // (burst_interval owns this regime).
        let cfg = cfg_default();
        let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
        let k = key("subfloor");
        record_n(&rec, &k, 7, 30);
        let p = RegularityProvider::new(Arc::clone(&rec), cfg);
        assert!(eval(&p, &k).is_empty());
    }

    #[test]
    fn silent_below_min_samples() {
        // 5 samples → 4 intervals, below the default 6-interval minimum.
        let cfg = cfg_default();
        let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
        let k = key("few");
        record_n(&rec, &k, 5, 200);
        let p = RegularityProvider::new(Arc::clone(&rec), cfg);
        assert!(eval(&p, &k).is_empty());
    }

    #[test]
    fn silent_when_disabled() {
        let cfg = Arc::new(ArcSwap::from_pointee(DeviceFpConfig {
            behavior: BehaviorConfig {
                regularity: RegularityCfg {
                    enabled: false,
                    ..RegularityCfg::default()
                },
                ..BehaviorConfig::default()
            },
            ..DeviceFpConfig::default()
        }));
        let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
        let k = key("off");
        record_n(&rec, &k, 7, 200);
        let p = RegularityProvider::new(Arc::clone(&rec), cfg);
        assert!(eval(&p, &k).is_empty());
    }

    #[test]
    fn silent_when_no_actor() {
        let cfg = cfg_default();
        let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
        let p = RegularityProvider::new(Arc::clone(&rec), cfg);
        assert!(eval(&p, &key("never-seen")).is_empty());
    }
}
