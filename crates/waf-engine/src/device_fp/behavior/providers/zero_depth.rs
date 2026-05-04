//! FR-RS-049 — zero-depth classifier.
//!
//! Fires when an actor has hammered exactly one Critical-tier path with
//! no Referer chain. The intuition: a real user navigating the app
//! generates path variation and at least one Referer-bearing transition;
//! a script targeting one endpoint does neither.
//!
//! Entry pages (`/`, `/login`, `/index`) are exempted at record time via
//! `Sample::is_entry_path` — they are legitimately zero-depth landings.

use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::device_fp::behavior::config::BehaviorConfig;
use crate::device_fp::behavior::recorder::Recorder;
use crate::device_fp::providers::SignalProvider;
use crate::device_fp::signal::Signal;
use crate::device_fp::types::DeviceCtx;
use waf_common::tier::Tier;

pub struct ZeroDepthProvider {
    recorder: Arc<Recorder>,
    cfg: Arc<ArcSwap<BehaviorConfig>>,
}

impl ZeroDepthProvider {
    #[must_use]
    pub const fn new(recorder: Arc<Recorder>, cfg: Arc<ArcSwap<BehaviorConfig>>) -> Self {
        Self { recorder, cfg }
    }
}

impl SignalProvider for ZeroDepthProvider {
    fn name(&self) -> &'static str {
        "zero_depth"
    }

    fn evaluate(&self, ctx: &DeviceCtx<'_>) -> Vec<Signal> {
        let cfg = self.cfg.load();
        let z = &cfg.zero_depth;
        if !z.enabled {
            return Vec::new();
        }

        let Some(snap) = self.recorder.snapshot(ctx.key) else {
            return Vec::new();
        };
        if snap.samples.len() < usize::from(z.min_samples) {
            return Vec::new();
        }

        // Single-path requirement uses the recorder's distinct-path
        // counter — true if and only if every observed path_hash matched
        // the first one in the actor's history.
        if snap.distinct_paths_len != 1 {
            return Vec::new();
        }

        // Any Referer in the entire window breaks the zero-depth pattern.
        if snap.samples.iter().any(|s| s.had_referer) {
            return Vec::new();
        }

        // Critical-tier hits are what make this risky — counting samples
        // (not intervals) so the threshold reads naturally.
        let critical_hits = snap.samples.iter().filter(|s| matches!(s.tier, Tier::Critical)).count();
        if critical_hits < usize::from(z.min_critical_samples) {
            return Vec::new();
        }

        // Legitimate landing pages are exempt — checked on the first
        // sample because by construction every sample shares its path.
        if snap.samples.first().is_some_and(|s| s.is_entry_path) {
            return Vec::new();
        }

        // u16-cap: WINDOW=16 caps `samples.len()`; far below u16::MAX.
        #[allow(clippy::cast_possible_truncation)]
        let count = snap.samples.len() as u16;
        vec![Signal::ZeroDepth { samples: count }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_fp::behavior::config::ZeroDepthCfg;
    use crate::device_fp::capture::ConnCtx;
    use crate::device_fp::types::{FingerprintValue, FpKey};
    use std::net::{IpAddr, Ipv4Addr};

    fn cfg_default() -> Arc<ArcSwap<BehaviorConfig>> {
        Arc::new(ArcSwap::from_pointee(BehaviorConfig::default()))
    }

    fn key(tag: &str) -> FpKey {
        FpKey {
            ja3: Some(FingerprintValue::new(tag)),
            ja4: None,
            h2_akamai: None,
        }
    }

    fn eval(p: &ZeroDepthProvider, k: &FpKey) -> Vec<Signal> {
        let conn = ConnCtx::new();
        let ctx = DeviceCtx::new(IpAddr::V4(Ipv4Addr::LOCALHOST), "ua", &conn, k);
        p.evaluate(&ctx)
    }

    fn drive(rec: &Arc<Recorder>, k: &FpKey, n: usize, path: &str, had_referer: bool, tier: Tier) {
        for _ in 0..n {
            rec.record(k, path, had_referer, false, tier);
        }
    }

    #[test]
    fn fires_on_single_critical_path_no_referer() {
        let cfg = cfg_default();
        let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
        let k = key("za");
        drive(&rec, &k, 4, "/admin/critical", false, Tier::Critical);
        let p = ZeroDepthProvider::new(Arc::clone(&rec), cfg);
        let signals = eval(&p, &k);
        assert_eq!(signals.len(), 1, "expected 1 signal, got {signals:?}");
        match signals.first() {
            Some(Signal::ZeroDepth { samples }) => assert!(*samples >= 4),
            other => panic!("wrong signal: {other:?}"),
        }
    }

    #[test]
    fn silent_when_referer_present() {
        let cfg = cfg_default();
        let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
        let k = key("zb");
        drive(&rec, &k, 4, "/admin/critical", true, Tier::Critical);
        let p = ZeroDepthProvider::new(Arc::clone(&rec), cfg);
        assert!(eval(&p, &k).is_empty());
    }

    #[test]
    fn silent_on_two_distinct_paths() {
        let cfg = cfg_default();
        let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
        let k = key("zc");
        drive(&rec, &k, 3, "/admin/critical", false, Tier::Critical);
        drive(&rec, &k, 1, "/admin/other", false, Tier::Critical);
        let p = ZeroDepthProvider::new(Arc::clone(&rec), cfg);
        assert!(eval(&p, &k).is_empty());
    }

    #[test]
    fn silent_when_only_medium_tier() {
        let cfg = cfg_default();
        let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
        let k = key("zd");
        drive(&rec, &k, 4, "/dashboard", false, Tier::Medium);
        let p = ZeroDepthProvider::new(Arc::clone(&rec), cfg);
        assert!(eval(&p, &k).is_empty());
    }

    #[test]
    fn silent_on_exempt_entry_path() {
        // /login is in the default exempt list — even with Critical tier
        // and no referer, this is a legitimate landing.
        let cfg = cfg_default();
        let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
        let k = key("ze");
        drive(&rec, &k, 4, "/login", false, Tier::Critical);
        let p = ZeroDepthProvider::new(Arc::clone(&rec), cfg);
        assert!(eval(&p, &k).is_empty());
    }

    #[test]
    fn silent_below_min_samples() {
        let cfg = cfg_default();
        let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
        let k = key("zf");
        drive(&rec, &k, 3, "/admin/critical", false, Tier::Critical);
        let p = ZeroDepthProvider::new(Arc::clone(&rec), cfg);
        assert!(eval(&p, &k).is_empty());
    }

    #[test]
    fn silent_when_disabled() {
        let cfg = Arc::new(ArcSwap::from_pointee(BehaviorConfig {
            zero_depth: ZeroDepthCfg {
                enabled: false,
                ..ZeroDepthCfg::default()
            },
            ..BehaviorConfig::default()
        }));
        let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
        let k = key("zg");
        drive(&rec, &k, 4, "/admin/critical", false, Tier::Critical);
        let p = ZeroDepthProvider::new(Arc::clone(&rec), cfg);
        assert!(eval(&p, &k).is_empty());
    }
}
