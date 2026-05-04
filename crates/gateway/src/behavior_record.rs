//! FR-011 phase-02 — Pingora ↔ behavioral `Recorder` glue.
//!
//! One free function so the wiring is testable without spinning up a real
//! Pingora `Session`. The proxy hot path calls `record_sample` exactly once
//! per request after `FpKey` resolution.

use std::sync::Arc;

use waf_common::tier::Tier;
use waf_engine::device_fp::FpKey;
use waf_engine::device_fp::behavior::Recorder;

/// Record one behavioral sample. No-ops when the recorder is unset (back-compat
/// fast path) or when `key.is_empty()` (skip unidentified-actor bucket per
/// plan §Security).
///
/// `had_prefetch_hint` reflects the `Sec-Purpose: prefetch` request header,
/// which the `missing_referer` classifier treats as an exemption (browsers
/// legitimately suppress Referer for prefetched navigations).
pub fn record_sample(
    recorder: Option<&Arc<Recorder>>,
    key: &FpKey,
    path: &str,
    had_referer: bool,
    had_prefetch_hint: bool,
    tier: Tier,
) {
    if let Some(rec) = recorder
        && !key.is_empty()
    {
        rec.record(key, path, had_referer, had_prefetch_hint, tier);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arc_swap::ArcSwap;
    use waf_engine::device_fp::FingerprintValue;
    use waf_engine::device_fp::config::DeviceFpConfig;

    fn make_recorder() -> Arc<Recorder> {
        Arc::new(Recorder::new(Arc::new(
            ArcSwap::from_pointee(DeviceFpConfig::default()),
        )))
    }

    fn key(tag: &str) -> FpKey {
        FpKey {
            ja3: Some(FingerprintValue::new(tag)),
            ja4: None,
            h2_akamai: None,
        }
    }

    #[test]
    fn three_records_produce_three_samples() {
        // Plan §Success Criteria: 3 requests → 3 samples in snapshot.
        let rec = make_recorder();
        let k = key("a");
        for _ in 0..3 {
            record_sample(Some(&rec), &k, "/x", false, false, Tier::CatchAll);
        }
        let snap = rec.snapshot(&k).expect("snapshot must exist after recording");
        assert_eq!(snap.samples.len(), 3);
    }

    #[test]
    fn empty_key_is_skipped() {
        // Plan §Security: empty FpKey must not create an entry.
        let rec = make_recorder();
        let empty = FpKey::default();
        record_sample(Some(&rec), &empty, "/x", false, false, Tier::CatchAll);
        assert!(rec.snapshot(&empty).is_none());
        assert!(rec.is_empty());
    }

    #[test]
    fn no_recorder_is_noop() {
        // Back-compat: gateways without an injected recorder just pass through.
        let k = key("a");
        record_sample(None, &k, "/x", false, false, Tier::CatchAll);
        // Reaching here without panic is the assertion.
    }

    #[test]
    fn referer_flag_propagates_to_sample() {
        let rec = make_recorder();
        let k = key("b");
        record_sample(Some(&rec), &k, "/x", true, false, Tier::CatchAll);
        let snap = rec.snapshot(&k).expect("snapshot");
        assert_eq!(snap.samples.len(), 1);
        assert!(snap.samples.first().expect("sample exists").had_referer);
    }

    #[test]
    fn tier_propagates_to_sample() {
        let rec = make_recorder();
        let k = key("c");
        record_sample(Some(&rec), &k, "/x", false, false, Tier::Critical);
        let snap = rec.snapshot(&k).expect("snapshot");
        assert_eq!(snap.samples.first().expect("sample exists").tier, Tier::Critical);
    }
}
