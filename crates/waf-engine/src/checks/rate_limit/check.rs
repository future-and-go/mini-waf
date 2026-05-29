//! `RateLimitCheck` — wires the FR-004 store + key builder into the WAF pipeline.
//!
//! For each request we build up to two keys (per-IP + per-session) and query
//! the store. **Block if either key is non-Allow.** IP key first so we shed
//! flood traffic before parsing cookies.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use waf_common::tier::FailMode;
use waf_common::{DetectionResult, Phase, RequestCtx};

use super::RateLimitConfig;
use super::key::KeyKind;
use super::store::{Decision, RateLimitStore};
use crate::checks::Check;

/// Rate-limit check. Holds a shared store handle + a hot-reloadable config
/// snapshot. The `ArcSwap` lets the reloader replace config without dropping
/// in-flight requests.
pub struct RateLimitCheck {
    store: Arc<dyn RateLimitStore>,
    cfg: Arc<ArcSwap<RateLimitConfig>>,
}

impl RateLimitCheck {
    pub const fn new(store: Arc<dyn RateLimitStore>, cfg: Arc<ArcSwap<RateLimitConfig>>) -> Self {
        Self { store, cfg }
    }

    /// Translate a non-Allow decision into a `DetectionResult`.
    fn block(rule_id: &'static str, scope: &str, decision: Decision) -> DetectionResult {
        let detail = match decision {
            Decision::BurstExceeded => format!("{scope} burst limit exceeded"),
            Decision::SustainedExceeded => format!("{scope} sustained window limit exceeded"),
            Decision::Allow => format!("{scope} allowed"), // unreachable in practice
        };
        DetectionResult {
            rule_id: Some(rule_id.to_string()),
            rule_name: "Rate Limit".to_string(),
            phase: Phase::RateLimit,
            detail,
            rule_action: None,
            action_status: None,
        }
    }

    /// FR-037: tier `fail_mode` decides whether a store error blocks or passes.
    fn handle_store_err(err: &anyhow::Error, ctx: &RequestCtx) -> Option<DetectionResult> {
        match ctx.tier_policy.fail_mode {
            FailMode::Close => {
                tracing::warn!(error = %err, tier = ?ctx.tier, "rate-limit store error: fail-closed");
                Some(DetectionResult {
                    rule_id: Some("RL-ERR".to_string()),
                    rule_name: "Rate Limit (store error)".to_string(),
                    phase: Phase::RateLimit,
                    detail: "rate-limit store error; tier fail_mode=close".to_string(),
                    rule_action: None,
                    action_status: None,
                })
            }
            FailMode::Open => {
                tracing::warn!(error = %err, tier = ?ctx.tier, "rate-limit store error: fail-open");
                None
            }
        }
    }
}

impl Check for RateLimitCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        // Single Arc load per request — readers never block writers.
        let snapshot = self.cfg.load();
        // Skip when this tier has no limit configured.
        let cfg = snapshot.for_tier(ctx.tier)?;

        let now_ms = now_epoch_ms();
        let host = ctx.host_config.code.as_str();

        // Per-IP first — cheaper short-circuit for flood traffic.
        let ip_key = KeyKind::Ip {
            host,
            ip: ctx.client_ip,
        }
        .render();
        match self.store.check_and_consume_blocking(&ip_key, cfg, now_ms) {
            Ok(Decision::Allow) => {}
            Ok(d) => return Some(Self::block("RL-IP", "per-IP", d)),
            Err(e) => return Self::handle_store_err(&e, ctx),
        }

        // Per-session, if we have a session id.
        let sid = ctx.cookies.get(&snapshot.session_cookie).map(String::as_str)?;
        let s_key = KeyKind::Session { host, session: sid }.render();
        match self.store.check_and_consume_blocking(&s_key, cfg, now_ms) {
            Ok(Decision::Allow) => None,
            Ok(d) => Some(Self::block("RL-SESSION", "per-session", d)),
            Err(e) => Self::handle_store_err(&e, ctx),
        }
    }

    fn reset_state(&self) {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.store.clear_all()).ok();
        });
    }
}

/// Current wall-clock epoch milliseconds, clamped to `i64`.
fn now_epoch_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::rate_limit::store::{LimitCfg, MemoryStore};
    use async_trait::async_trait;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use waf_common::HostConfig;
    use waf_common::tier::{CachePolicy, RiskThresholds, Tier, TierPolicy};

    fn cfg_for_tier(tier: Tier) -> Arc<ArcSwap<RateLimitConfig>> {
        let mut tiers = HashMap::new();
        tiers.insert(
            tier,
            LimitCfg {
                burst_capacity: 2,
                burst_refill_per_s: 0.0,
                window_secs: 60,
                window_limit: 1_000,
            },
        );
        Arc::new(ArcSwap::from(Arc::new(RateLimitConfig {
            session_cookie: "SID".to_string(),
            tiers,
        })))
    }

    fn make_ctx(tier: Tier, fail_mode: FailMode, with_cookie: bool) -> RequestCtx {
        let mut cookies = HashMap::new();
        if with_cookie {
            cookies.insert("SID".to_string(), "user-1".to_string());
        }
        let policy = TierPolicy {
            fail_mode,
            ddos_threshold_rps: u32::MAX,
            cache_policy: CachePolicy::NoCache,
            risk_thresholds: RiskThresholds {
                allow: 30,
                challenge: 70,
                block: 90,
            },
        };
        RequestCtx {
            req_id: "t".to_string(),
            client_ip: "10.0.0.1"
                .parse::<IpAddr>()
                .unwrap_or_else(|_| IpAddr::from([0, 0, 0, 0])),
            client_port: 0,
            method: "GET".to_string(),
            host: "h".to_string(),
            port: 80,
            path: "/".to_string(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config: Arc::new(HostConfig {
                code: "host-a".to_string(),
                ..HostConfig::default()
            }),
            geo: None,
            tier,
            tier_policy: Arc::new(policy),
            cookies,
        }
    }

    /// Mocked store returning a scripted sequence of results.
    struct ScriptedStore {
        calls: AtomicUsize,
        script: Vec<anyhow::Result<Decision>>,
    }
    impl ScriptedStore {
        fn new(script: Vec<anyhow::Result<Decision>>) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                script,
            }
        }
        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }
    #[async_trait]
    impl RateLimitStore for ScriptedStore {
        async fn check_and_consume(&self, _k: &str, _c: &LimitCfg, _t: i64) -> anyhow::Result<Decision> {
            let i = self.calls.fetch_add(1, Ordering::SeqCst);
            match self.script.get(i) {
                Some(Ok(d)) => Ok(*d),
                Some(Err(e)) => Err(anyhow::anyhow!(e.to_string())),
                None => Ok(Decision::Allow),
            }
        }
        fn check_and_consume_blocking(&self, _k: &str, _c: &LimitCfg, _t: i64) -> anyhow::Result<Decision> {
            let i = self.calls.fetch_add(1, Ordering::SeqCst);
            match self.script.get(i) {
                Some(Ok(d)) => Ok(*d),
                Some(Err(e)) => Err(anyhow::anyhow!(e.to_string())),
                None => Ok(Decision::Allow),
            }
        }
        async fn purge_expired(&self) -> anyhow::Result<usize> {
            Ok(0)
        }
    }

    #[test]
    fn skips_when_tier_unconfigured() {
        // Config has Critical, request is CatchAll → no check runs.
        let cfg = cfg_for_tier(Tier::Critical);
        let store = Arc::new(ScriptedStore::new(vec![]));
        let check = RateLimitCheck::new(store.clone(), cfg);
        let ctx = make_ctx(Tier::CatchAll, FailMode::Open, false);
        assert!(check.check(&ctx).is_none());
        assert_eq!(store.call_count(), 0, "store must not be called");
    }

    #[test]
    fn allow_then_allow_passes() {
        let cfg = cfg_for_tier(Tier::CatchAll);
        let store = Arc::new(ScriptedStore::new(vec![Ok(Decision::Allow), Ok(Decision::Allow)]));
        let check = RateLimitCheck::new(store.clone(), cfg);
        let ctx = make_ctx(Tier::CatchAll, FailMode::Open, true);
        assert!(check.check(&ctx).is_none());
        assert_eq!(store.call_count(), 2, "IP + session both queried");
    }

    #[test]
    fn ip_burst_blocks_before_session_query() {
        let cfg = cfg_for_tier(Tier::CatchAll);
        let store = Arc::new(ScriptedStore::new(vec![Ok(Decision::BurstExceeded)]));
        let check = RateLimitCheck::new(store.clone(), cfg);
        let ctx = make_ctx(Tier::CatchAll, FailMode::Open, true);
        let result = check.check(&ctx).expect("must block on IP burst");
        assert_eq!(result.rule_id.as_deref(), Some("RL-IP"));
        assert_eq!(store.call_count(), 1, "session must NOT be queried after IP block");
    }

    #[test]
    fn session_sustained_blocks() {
        let cfg = cfg_for_tier(Tier::CatchAll);
        let store = Arc::new(ScriptedStore::new(vec![
            Ok(Decision::Allow),
            Ok(Decision::SustainedExceeded),
        ]));
        let check = RateLimitCheck::new(store, cfg);
        let ctx = make_ctx(Tier::CatchAll, FailMode::Open, true);
        let result = check.check(&ctx).expect("must block on session sustained");
        assert_eq!(result.rule_id.as_deref(), Some("RL-SESSION"));
    }

    #[test]
    fn no_cookie_runs_only_ip_key() {
        let cfg = cfg_for_tier(Tier::CatchAll);
        let store = Arc::new(ScriptedStore::new(vec![Ok(Decision::Allow)]));
        let check = RateLimitCheck::new(store.clone(), cfg);
        let ctx = make_ctx(Tier::CatchAll, FailMode::Open, false);
        assert!(check.check(&ctx).is_none());
        assert_eq!(store.call_count(), 1, "no cookie → only IP key");
    }

    #[test]
    fn store_err_fail_open_passes() {
        let cfg = cfg_for_tier(Tier::CatchAll);
        let store = Arc::new(ScriptedStore::new(vec![Err(anyhow::anyhow!("backend down"))]));
        let check = RateLimitCheck::new(store, cfg);
        let ctx = make_ctx(Tier::CatchAll, FailMode::Open, true);
        assert!(check.check(&ctx).is_none(), "fail-open must pass on store error");
    }

    #[test]
    fn store_err_fail_close_blocks() {
        let cfg = cfg_for_tier(Tier::CatchAll);
        let store = Arc::new(ScriptedStore::new(vec![Err(anyhow::anyhow!("backend down"))]));
        let check = RateLimitCheck::new(store, cfg);
        let ctx = make_ctx(Tier::CatchAll, FailMode::Close, true);
        let result = check.check(&ctx).expect("fail-close must block");
        assert_eq!(result.rule_id.as_deref(), Some("RL-ERR"));
    }

    /// Engine-level integration: real `MemoryStore`, request allowed under
    /// limit then blocked over limit.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn integration_under_then_over_limit() {
        let store = Arc::new(MemoryStore::new());
        let mut tiers = HashMap::new();
        tiers.insert(
            Tier::CatchAll,
            LimitCfg {
                burst_capacity: 2,
                burst_refill_per_s: 0.0,
                window_secs: 60,
                window_limit: 1_000,
            },
        );
        let cfg = Arc::new(ArcSwap::from(Arc::new(RateLimitConfig {
            session_cookie: "SID".to_string(),
            tiers,
        })));
        let check = RateLimitCheck::new(store, cfg);
        let ctx = make_ctx(Tier::CatchAll, FailMode::Open, false);
        // burst=2 → first 2 allowed. Each call consumes 1 IP token.
        assert!(check.check(&ctx).is_none());
        assert!(check.check(&ctx).is_none());
        let result = check.check(&ctx).expect("3rd request must be blocked");
        assert_eq!(result.rule_id.as_deref(), Some("RL-IP"));
    }
}
