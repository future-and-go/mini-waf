//! Shared conformance scenarios for `RateLimitStore` implementations.
//!
//! Both the in-memory (phase 03) and Redis (phase 06) backends MUST pass the
//! same suite. Tests are async + black-box: they only touch the trait surface
//! so swapping impls requires no test edits.
//!
//! Seven scenarios — see `run_conformance` body for the list. All scenarios
//! pass `now_ms` explicitly to the store so timing is deterministic; we never
//! call `Instant::now()` or sleep.

#![cfg(test)]

use std::sync::Arc;

use crate::checks::rate_limit::store::{Decision, LimitCfg, RateLimitStore};

/// Runs the full 7-scenario conformance suite against `store`.
/// Panics on any assertion failure.
pub async fn run_conformance(store: Arc<dyn RateLimitStore>) {
    basic_allow(&store).await;
    burst_exceeded(&store).await;
    burst_refill(&store).await;
    sustained_exceeded(&store).await;
    window_roll(&store).await;
    key_isolation(&store).await;
    concurrent_hammer(&store).await;
}

// ── 1. basic allow — comfortable budget, every request passes ──────────────
async fn basic_allow(store: &Arc<dyn RateLimitStore>) {
    let cfg = LimitCfg {
        burst_capacity: 5,
        burst_refill_per_s: 1.0,
        window_secs: 60,
        window_limit: 100,
    };
    for _ in 0..3 {
        let d = store.check_and_consume("c1:basic", &cfg, 0).await.unwrap();
        assert_eq!(d, Decision::Allow);
    }
}

// ── 2. burst exceeded — bucket=2, 5 fast hits → 2 Allow, 3 BurstExceeded ───
async fn burst_exceeded(store: &Arc<dyn RateLimitStore>) {
    let cfg = LimitCfg {
        burst_capacity: 2,
        burst_refill_per_s: 0.1,
        window_secs: 60,
        window_limit: 100,
    };
    let mut allow = 0;
    let mut burst = 0;
    // Fixed `now_ms` => zero refill across the 5 calls.
    for _ in 0..5 {
        match store.check_and_consume("c2:burst", &cfg, 0).await.unwrap() {
            Decision::Allow => allow += 1,
            Decision::BurstExceeded => burst += 1,
            Decision::SustainedExceeded => panic!("unexpected SustainedExceeded"),
        }
    }
    assert_eq!(allow, 2, "expected 2 Allow");
    assert_eq!(burst, 3, "expected 3 BurstExceeded");
}

// ── 3. burst refill — empty bucket recovers exactly one token per second ───
async fn burst_refill(store: &Arc<dyn RateLimitStore>) {
    let cfg = LimitCfg {
        burst_capacity: 1,
        burst_refill_per_s: 1.0,
        window_secs: 60,
        window_limit: 100,
    };
    // t=0: bucket full → consume → empty.
    assert_eq!(
        store.check_and_consume("c3:refill", &cfg, 0).await.unwrap(),
        Decision::Allow
    );
    // t=500ms: only 0.5 token refilled → still empty.
    assert_eq!(
        store.check_and_consume("c3:refill", &cfg, 500).await.unwrap(),
        Decision::BurstExceeded
    );
    // t=1100ms: 1.1 tokens since last refill point → allowed.
    assert_eq!(
        store.check_and_consume("c3:refill", &cfg, 1_100).await.unwrap(),
        Decision::Allow
    );
}

// ── 4. sustained exceeded — large burst, tight window cap ──────────────────
async fn sustained_exceeded(store: &Arc<dyn RateLimitStore>) {
    let cfg = LimitCfg {
        burst_capacity: 1_000,
        burst_refill_per_s: 1_000.0,
        window_secs: 10,
        window_limit: 3,
    };
    let mut allow = 0;
    let mut sustained = 0;
    for _ in 0..4 {
        match store.check_and_consume("c4:sust", &cfg, 0).await.unwrap() {
            Decision::Allow => allow += 1,
            Decision::SustainedExceeded => sustained += 1,
            Decision::BurstExceeded => panic!("unexpected BurstExceeded — burst should not bind"),
        }
    }
    assert_eq!(allow, 3, "expected 3 Allow");
    assert_eq!(sustained, 1, "expected 1 SustainedExceeded");
}

// ── 5. window roll — after >1 full window passes, counter resets ───────────
async fn window_roll(store: &Arc<dyn RateLimitStore>) {
    let cfg = LimitCfg {
        burst_capacity: 1_000,
        burst_refill_per_s: 1_000.0,
        window_secs: 10,
        window_limit: 2,
    };
    // Two requests at t=0 fill the window exactly to the cap.
    for _ in 0..2 {
        assert_eq!(
            store.check_and_consume("c5:roll", &cfg, 0).await.unwrap(),
            Decision::Allow
        );
    }
    // Jump >1 full window forward — any reasonable backend (sliding-window
    // weighted, fixed-window counter, request log) must consider the prior
    // window stale and admit the request.
    assert_eq!(
        store.check_and_consume("c5:roll", &cfg, 20_000).await.unwrap(),
        Decision::Allow
    );
}

// ── 6. key isolation — pressure on key A leaves key B untouched ────────────
async fn key_isolation(store: &Arc<dyn RateLimitStore>) {
    let cfg = LimitCfg {
        burst_capacity: 5,
        burst_refill_per_s: 0.0,
        window_secs: 60,
        window_limit: 1_000,
    };
    // Hammer key A — irrelevant which decisions come back, just generate load.
    for _ in 0..100 {
        let _ = store.check_and_consume("c6:A", &cfg, 0).await.unwrap();
    }
    // Key B starts fresh: must Allow.
    assert_eq!(store.check_and_consume("c6:B", &cfg, 0).await.unwrap(), Decision::Allow);
}

// ── 7. concurrent hammer — many tasks, no panics, allow count bounded ──────
async fn concurrent_hammer(store: &Arc<dyn RateLimitStore>) {
    let cfg = LimitCfg {
        burst_capacity: 100,
        burst_refill_per_s: 0.0,
        window_secs: 60,
        window_limit: 1_000,
    };
    let mut handles = Vec::with_capacity(200);
    for _ in 0..200 {
        let s = Arc::clone(store);
        let c = cfg.clone();
        handles.push(tokio::spawn(async move {
            let mut allowed = 0_u32;
            for _ in 0..10 {
                if matches!(s.check_and_consume("c7:hot", &c, 0).await.unwrap(), Decision::Allow) {
                    allowed += 1;
                }
            }
            allowed
        }));
    }
    let mut total_allowed = 0_u32;
    for h in handles {
        total_allowed += h.await.unwrap();
    }
    // With burst=100 and zero refill at fixed t=0, exactly 100 should pass —
    // any more = double-counting; any fewer = lost increment under contention.
    assert_eq!(
        total_allowed, 100,
        "expected exactly burst_capacity allows under hammer"
    );
}
