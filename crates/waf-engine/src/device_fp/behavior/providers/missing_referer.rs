//! FR-011 — missing-referer classifier.
//!
//! Fires the first time an unidentified actor lands on a non-exempt path
//! without sending a Referer header. Real users almost always arrive
//! either from another page (Referer set) or onto a known entry point;
//! scripts hitting `/dashboard/profile` cold rarely set a Referer.
//!
//! "Session" identity v1 = the device fingerprint (`FpKey`). No WAF
//! cookie. Reason: KISS — the `FpKey` is already our session-equivalent.
//! `Sec-Purpose: prefetch` is honoured as an exemption: the spec
//! explicitly suppresses Referer for prefetched navigations.
//!
//! Order invariant: this provider must run **after** the recorder write
//! that captured the current request — it relies on `samples.len() == 1`
//! to detect "first observation". Phase 4 swaps the proxy ordering to
//! enforce this.

use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::device_fp::behavior::config::BehaviorConfig;
use crate::device_fp::behavior::recorder::Recorder;
use crate::device_fp::providers::SignalProvider;
use crate::device_fp::signal::Signal;
use crate::device_fp::types::DeviceCtx;

pub struct MissingRefererProvider {
    recorder: Arc<Recorder>,
    cfg: Arc<ArcSwap<BehaviorConfig>>,
}

impl MissingRefererProvider {
    #[must_use]
    pub const fn new(recorder: Arc<Recorder>, cfg: Arc<ArcSwap<BehaviorConfig>>) -> Self {
        Self { recorder, cfg }
    }
}

impl SignalProvider for MissingRefererProvider {
    fn name(&self) -> &'static str {
        "missing_referer"
    }

    fn evaluate(&self, ctx: &DeviceCtx<'_>) -> Vec<Signal> {
        let cfg = self.cfg.load();
        let m = &cfg.missing_referer;
        if !m.enabled {
            return Vec::new();
        }

        let Some(snap) = self.recorder.snapshot(ctx.key) else {
            return Vec::new();
        };
        // First request only — scope is "first nav in session".
        if snap.samples.len() != 1 {
            return Vec::new();
        }
        let Some(sample) = snap.samples.first() else {
            return Vec::new();
        };

        if sample.had_referer || sample.had_prefetch_hint || sample.is_low_signal_path {
            return Vec::new();
        }

        vec![Signal::MissingReferer]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_fp::behavior::config::MissingRefererCfg;
    use crate::device_fp::capture::ConnCtx;
    use crate::device_fp::types::{FingerprintValue, FpKey};
    use std::net::{IpAddr, Ipv4Addr};
    use waf_common::tier::Tier;

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

    fn eval(p: &MissingRefererProvider, k: &FpKey) -> Vec<Signal> {
        let conn = ConnCtx::new();
        let ctx = DeviceCtx::new(IpAddr::V4(Ipv4Addr::LOCALHOST), "ua", &conn, k);
        p.evaluate(&ctx)
    }

    #[test]
    fn fires_on_first_nav_without_referer() {
        let cfg = cfg_default();
        let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
        let k = key("ma");
        rec.record(&k, "/dashboard/profile", false, false, Tier::High);
        let p = MissingRefererProvider::new(Arc::clone(&rec), cfg);
        let signals = eval(&p, &k);
        assert_eq!(signals.len(), 1, "expected 1 signal, got {signals:?}");
        assert!(matches!(signals.first(), Some(Signal::MissingReferer)));
    }

    #[test]
    fn silent_when_referer_present() {
        let cfg = cfg_default();
        let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
        let k = key("mb");
        rec.record(&k, "/dashboard/profile", true, false, Tier::High);
        let p = MissingRefererProvider::new(Arc::clone(&rec), cfg);
        assert!(eval(&p, &k).is_empty());
    }

    #[test]
    fn silent_on_exempt_path() {
        let cfg = cfg_default();
        let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
        let k = key("mc");
        rec.record(&k, "/login", false, false, Tier::High);
        let p = MissingRefererProvider::new(Arc::clone(&rec), cfg);
        assert!(eval(&p, &k).is_empty());
    }

    #[test]
    fn silent_on_exempt_prefix() {
        let cfg = cfg_default();
        let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
        let k = key("md");
        rec.record(&k, "/static/css/app.css", false, false, Tier::CatchAll);
        let p = MissingRefererProvider::new(Arc::clone(&rec), cfg);
        assert!(eval(&p, &k).is_empty());
    }

    #[test]
    fn silent_on_prefetch_hint() {
        let cfg = cfg_default();
        let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
        let k = key("me");
        rec.record(&k, "/dashboard/profile", false, true, Tier::High);
        let p = MissingRefererProvider::new(Arc::clone(&rec), cfg);
        assert!(eval(&p, &k).is_empty());
    }

    #[test]
    fn silent_on_subsequent_request() {
        // Second sample → samples.len() == 2 → "first nav" no longer holds.
        let cfg = cfg_default();
        let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
        let k = key("mf");
        rec.record(&k, "/dashboard/profile", false, false, Tier::High);
        rec.record(&k, "/dashboard/orders", false, false, Tier::High);
        let p = MissingRefererProvider::new(Arc::clone(&rec), cfg);
        assert!(eval(&p, &k).is_empty());
    }

    #[test]
    fn silent_when_no_actor() {
        let cfg = cfg_default();
        let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
        let p = MissingRefererProvider::new(Arc::clone(&rec), cfg);
        assert!(eval(&p, &key("never-seen")).is_empty());
    }

    #[test]
    fn silent_when_disabled() {
        let cfg = Arc::new(ArcSwap::from_pointee(BehaviorConfig {
            missing_referer: MissingRefererCfg {
                enabled: false,
                ..MissingRefererCfg::default()
            },
            ..BehaviorConfig::default()
        }));
        let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
        let k = key("mg");
        rec.record(&k, "/dashboard/profile", false, false, Tier::High);
        let p = MissingRefererProvider::new(Arc::clone(&rec), cfg);
        assert!(eval(&p, &k).is_empty());
    }
}
