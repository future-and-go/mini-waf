# Phase 04 — Key Builder + RateLimitCheck Integration

**Priority:** P0 | **Status:** pending | **Depends:** 03

## Goal

`RateLimitCheck` impl `Check` trait. For each request, build IP key + session key, query store twice, return `DetectionResult`. Wired into engine check chain in parallel with old `cc.rs` (old still active, no removal yet).

## Requirements

- Read session id from configurable cookie name; if missing, fall back to `device_fp` hex (already present in `RequestCtx`)
- Both keys checked; **block** if **either** non-Allow
- Surface which key tripped + which algo (for audit log FR-032)
- Time source: `chrono::Utc::now().timestamp_millis()` — single call per request, passed down
- No new allocations on hot path beyond the two `String` keys

## Files

**Create:**
- `crates/waf-engine/src/checks/rate_limit/check.rs`

**Modify:**
- `crates/waf-engine/src/checks/rate_limit/mod.rs` — `pub mod check; pub use check::RateLimitCheck;`
- `crates/waf-engine/src/checks/mod.rs` — register `RateLimitCheck` in check registry alongside `CcCheck`

## Implementation Sketch

```rust
use std::sync::Arc;
use async_trait::async_trait;
use waf_common::{DetectionResult, Phase, RequestCtx};

use super::key::KeyKind;
use super::store::{Decision, LimitCfg, RateLimitStore};
use super::Check;

pub struct RateLimitCheck {
    store: Arc<dyn RateLimitStore>,
    cfg: Arc<RateLimitConfig>, // tier -> LimitCfg, session_cookie name
}

impl RateLimitCheck {
    fn session_id<'a>(&self, ctx: &'a RequestCtx) -> Option<&'a str> {
        ctx.cookie(&self.cfg.session_cookie)
            .or_else(|| ctx.device_fp_hex())
    }
}

#[async_trait]
impl Check for RateLimitCheck {
    fn phase(&self) -> Phase { Phase::Request }

    async fn run(&self, ctx: &RequestCtx) -> DetectionResult {
        let cfg = self.cfg.for_tier(ctx.tier());
        let now_ms = ctx.now_ms();
        let host = ctx.host_code();

        let ip_key = KeyKind::Ip { host, ip: ctx.client_ip() }.render();
        match self.store.check_and_consume(&ip_key, &cfg, now_ms).await {
            Ok(Decision::Allow) => {}
            Ok(d) => return DetectionResult::block_with("rate_limit_ip", d),
            Err(e) => return self.handle_store_err(e, ctx),  // tier fail-mode
        }

        if let Some(sid) = self.session_id(ctx) {
            let s_key = KeyKind::Session { host, session: sid }.render();
            match self.store.check_and_consume(&s_key, &cfg, now_ms).await {
                Ok(Decision::Allow) => DetectionResult::pass(),
                Ok(d) => DetectionResult::block_with("rate_limit_session", d),
                Err(e) => self.handle_store_err(e, ctx),
            }
        } else {
            DetectionResult::pass()
        }
    }
}
```

## Critical Details

- `ctx.cookie(name)` and `ctx.device_fp_hex()` may not yet exist on `RequestCtx`. If missing → add minimal accessors in `waf-common/src/types.rs`. Surgical: don't refactor surrounding API.
- `handle_store_err`: if tier `fail_mode == "close"` → block; else → pass + log warn (FR-037)
- IP key checked first to deny earliest possible (cheaper than parsing cookies on attacker traffic)

## Tests

- Mocked store returning `Allow/BurstExceeded/SustainedExceeded/Err` → check produces correct `DetectionResult`
- Cookie present → uses cookie session
- Cookie absent + `device_fp` present → uses fp
- Both absent → only IP-keyed check runs

## Verify

```bash
cargo test -p waf-engine rate_limit::check
cargo clippy -p waf-engine --all-features -- -D warnings
```

## Done When

- [ ] `RateLimitCheck` registered alongside `CcCheck`, both run, no panic
- [ ] Engine-level integration test: request allowed under limit, blocked over limit
- [ ] Tier fail-mode: simulated store error → close blocks, open allows
