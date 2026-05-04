//! FR-012 phase-03 — `TxVelocityCheck` integrates the transaction velocity
//! recorder into the WAF checker pipeline.
//!
//! This check is **signal-only**: it never blocks requests directly.
//! Instead, it records transaction events and emits risk signals to the
//! aggregator when classifiers detect anomalies (velocity breach, suspicious
//! sequence timing, etc.). Blocking decisions are made downstream by the
//! risk engine.
//!
//! Insert position: after `RateLimitCheck`, before `ScannerCheck` — this
//! ensures flood traffic is shed first, but velocity tracking runs before
//! expensive pattern-matching checks.

use std::sync::Arc;

use arc_swap::ArcSwap;
use waf_common::{DetectionResult, RequestCtx};

use super::config::TxVelocityConfig;
use super::recorder::TxStore;
use super::session_key::extract_session_key;
use crate::checks::Check;

/// Transaction velocity check. Signal-only — records events and emits
/// risk signals, never blocks directly.
///
/// Holds shared references to the hot-reloadable config and the in-memory
/// transaction store. The store runs classifiers internally on `record()`.
pub struct TxVelocityCheck {
    cfg: Arc<ArcSwap<TxVelocityConfig>>,
    store: Arc<TxStore>,
}

impl TxVelocityCheck {
    #[must_use]
    pub const fn new(cfg: Arc<ArcSwap<TxVelocityConfig>>, store: Arc<TxStore>) -> Self {
        Self { cfg, store }
    }
}

impl Check for TxVelocityCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        let snapshot = self.cfg.load();
        if !snapshot.enabled {
            return None;
        }

        // Classify the endpoint role from the request path.
        let role = snapshot.role_tagger.classify(&ctx.path);
        if matches!(role, super::EndpointRole::None) {
            return None;
        }

        // Extract session identity (cookie preferred, then fingerprint).
        // TODO: FR-010 integration — pass actual FpKey when device_fp is wired.
        let key = extract_session_key(ctx, &snapshot.session_cookie, None)?;

        // Record the event. Classifiers run inside the store and emit signals
        // to the aggregator asynchronously. `ok = true` at request-entry;
        // response-side enrichment deferred to a follow-up phase.
        self.store.record(&key, role, true);

        // Signal-only: never block here.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::tx_velocity::EndpointRole;
    use crate::checks::tx_velocity::config::{RoleRule, TxVelocityFileConfig};
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use waf_common::HostConfig;
    use waf_common::tier::{Tier, TierPolicy};

    fn cfg_enabled(session_cookie: &str, roles: &[RoleRule]) -> Arc<ArcSwap<TxVelocityConfig>> {
        let yaml = format!(
            r"
tx_velocity:
  enabled: true
  session_cookie: {session_cookie}
  endpoint_roles:
{roles_yaml}
",
            roles_yaml = roles
                .iter()
                .map(|r| format!("    - role: {:?}\n      path: \"{}\"", r.role, r.path).to_lowercase())
                .collect::<Vec<_>>()
                .join("\n")
        );
        let cfg = TxVelocityFileConfig::from_yaml_str(&yaml).expect("parse cfg");
        Arc::new(ArcSwap::from(cfg))
    }

    fn ctx_with_path_and_cookie(path: &str, cookie_name: &str, cookie_val: &str) -> RequestCtx {
        let mut cookies = HashMap::new();
        cookies.insert(cookie_name.to_string(), cookie_val.to_string());
        RequestCtx {
            req_id: "r".to_string(),
            client_ip: IpAddr::from([10, 0, 0, 1]),
            client_port: 12345,
            method: "POST".to_string(),
            host: "api.example.com".to_string(),
            port: 443,
            path: path.to_string(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: true,
            host_config: Arc::new(HostConfig::default()),
            geo: None,
            tier: Tier::CatchAll,
            tier_policy: Arc::new(TierPolicy::default()),
            cookies,
        }
    }

    #[test]
    fn disabled_config_skips_recording() {
        let cfg = Arc::new(ArcSwap::from_pointee(TxVelocityConfig::default()));
        let store = Arc::new(TxStore::new(Arc::clone(&cfg)));
        let check = TxVelocityCheck::new(cfg, Arc::clone(&store));

        let ctx = ctx_with_path_and_cookie("/api/login", "SID", "user123");
        assert!(check.check(&ctx).is_none());
        assert!(store.is_empty(), "store should remain empty when disabled");
    }

    #[test]
    fn unmatched_path_skips_recording() {
        let cfg = cfg_enabled(
            "SID",
            &[RoleRule {
                role: EndpointRole::Login,
                path: "^/api/login$".to_string(),
            }],
        );
        let store = Arc::new(TxStore::new(Arc::clone(&cfg)));
        let check = TxVelocityCheck::new(cfg, Arc::clone(&store));

        let ctx = ctx_with_path_and_cookie("/api/other", "SID", "user123");
        assert!(check.check(&ctx).is_none());
        assert!(store.is_empty(), "unmatched path should not record");
    }

    #[test]
    fn missing_session_skips_recording() {
        let cfg = cfg_enabled(
            "SID",
            &[RoleRule {
                role: EndpointRole::Login,
                path: "^/api/login$".to_string(),
            }],
        );
        let store = Arc::new(TxStore::new(Arc::clone(&cfg)));
        let check = TxVelocityCheck::new(cfg, Arc::clone(&store));

        // No cookie or fingerprint
        let ctx = RequestCtx {
            cookies: HashMap::new(),
            ..ctx_with_path_and_cookie("/api/login", "SID", "")
        };
        assert!(check.check(&ctx).is_none());
        assert!(store.is_empty(), "no session identity should skip recording");
    }

    #[test]
    fn matching_path_and_session_records_event() {
        let cfg = cfg_enabled(
            "SID",
            &[
                RoleRule {
                    role: EndpointRole::Login,
                    path: "^/api/login$".to_string(),
                },
                RoleRule {
                    role: EndpointRole::Otp,
                    path: "^/api/otp".to_string(),
                },
            ],
        );
        let store = Arc::new(TxStore::new(Arc::clone(&cfg)));
        let check = TxVelocityCheck::new(cfg, Arc::clone(&store));

        let ctx = ctx_with_path_and_cookie("/api/login", "SID", "user123");
        let result = check.check(&ctx);
        assert!(result.is_none(), "check should never block");
        assert_eq!(store.len(), 1, "event should be recorded");
    }

    #[test]
    fn check_always_returns_none() {
        let cfg = cfg_enabled(
            "SID",
            &[RoleRule {
                role: EndpointRole::Withdrawal,
                path: "^/api/withdraw".to_string(),
            }],
        );
        let store = Arc::new(TxStore::new(Arc::clone(&cfg)));
        let check = TxVelocityCheck::new(cfg, Arc::clone(&store));

        // Multiple hits should all return None (signal-only).
        for _ in 0..10 {
            let ctx = ctx_with_path_and_cookie("/api/withdraw", "SID", "user456");
            assert!(check.check(&ctx).is_none());
        }
    }
}
