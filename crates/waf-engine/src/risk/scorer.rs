//! FR-025 Scorer orchestrator.
//!
//! Builds `RiskKey` from request context, calls store, applies threshold gate,
//! sets `X-WAF-Risk-Score` header, returns `WafAction`.

use std::sync::Arc;

use arc_swap::ArcSwap;

use waf_common::{RequestCtx, WafAction};

use crate::device_fp::types::FpKey;
use crate::risk::config::RiskConfig;
use crate::risk::key::{RiskKey, SessionId};
use crate::risk::state::Contributor;
use crate::risk::store::RiskStore;
use crate::risk::threshold::decide;

/// Result of scoring a request.
#[derive(Clone, Debug)]
pub struct ScorerResult {
    /// The action to take based on risk score.
    pub action: WafAction,
    /// The clamped risk score (0..=100).
    pub score: u8,
    /// Whether this was a new actor (first request).
    pub is_new: bool,
}

/// Scorer orchestrator for the risk scoring pipeline.
///
/// Owns a reference to the store and config snapshot. Thread-safe via `Arc`.
pub struct Scorer<S: RiskStore> {
    store: Arc<S>,
    cfg: Arc<ArcSwap<RiskConfig>>,
}

impl<S: RiskStore> Scorer<S> {
    /// Create a new scorer with the given store and config.
    #[must_use]
    pub const fn new(store: Arc<S>, cfg: Arc<ArcSwap<RiskConfig>>) -> Self {
        Self { store, cfg }
    }

    /// Load the current config snapshot.
    #[must_use]
    pub fn config(&self) -> Arc<RiskConfig> {
        self.cfg.load_full()
    }

    /// Score a request and return the result.
    ///
    /// # Arguments
    /// * `ctx` - The request context (contains IP, tier, cookies)
    /// * `fp_key` - Optional device fingerprint key
    /// * `sync_deltas` - Risk deltas from earlier checks (e.g., rule matches)
    /// * `now_ms` - Current timestamp in milliseconds
    pub async fn score(
        &self,
        ctx: &RequestCtx,
        fp_key: Option<&FpKey>,
        sync_deltas: &[Contributor],
        now_ms: i64,
    ) -> anyhow::Result<ScorerResult> {
        let cfg = self.config();

        if !cfg.enabled {
            return Ok(ScorerResult {
                action: WafAction::Allow,
                score: 0,
                is_new: false,
            });
        }

        let key = Self::build_key(ctx, fp_key, &cfg);

        if key.is_empty() {
            return Ok(ScorerResult {
                action: WafAction::Allow,
                score: 0,
                is_new: true,
            });
        }

        let result = self.store.apply(&key, sync_deltas, now_ms).await?;
        let state = &result.state;

        let override_block = state.is_pinned(now_ms);
        let thresholds = &ctx.tier_policy.risk_thresholds;
        let action = decide(state.clamped_score, thresholds, override_block);

        Ok(ScorerResult {
            action,
            score: state.clamped_score,
            is_new: result.is_new,
        })
    }

    /// Build a `RiskKey` from request context.
    fn build_key(ctx: &RequestCtx, fp_key: Option<&FpKey>, cfg: &RiskConfig) -> RiskKey {
        let mut key = RiskKey::from_ip(ctx.client_ip);

        if let Some(fp) = fp_key {
            key.fp_hash = RiskKey::hash_fp_key(fp);
        }

        if let Some(ref cookie_name) = cfg.session_cookie
            && let Some(session_value) = ctx.cookies.get(cookie_name)
        {
            key.session = Some(SessionId::new(session_value.as_bytes().to_vec()));
        }

        key
    }

    /// Read the current risk state without applying any deltas.
    pub async fn read(&self, ctx: &RequestCtx, fp_key: Option<&FpKey>) -> anyhow::Result<Option<u8>> {
        let cfg = self.config();

        if !cfg.enabled {
            return Ok(None);
        }

        let key = Self::build_key(ctx, fp_key, &cfg);

        if key.is_empty() {
            return Ok(None);
        }

        let state = self.store.read(&key).await?;
        Ok(state.map(|s| s.clamped_score))
    }

    /// Force max score for an actor (honeypot trap).
    pub async fn force_max(
        &self,
        ctx: &RequestCtx,
        fp_key: Option<&FpKey>,
        until_ms: i64,
        now_ms: i64,
    ) -> anyhow::Result<()> {
        let cfg = self.config();
        let key = Self::build_key(ctx, fp_key, &cfg);

        if key.is_empty() {
            return Ok(());
        }

        self.store.force_max(&key, until_ms, now_ms).await
    }

    /// Get the header name for the risk score.
    #[must_use]
    pub fn header_name(&self) -> String {
        self.config().header_name.clone()
    }

    /// Check if header emission is enabled.
    #[must_use]
    pub fn emit_header(&self) -> bool {
        self.config().emit_header
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk::store::MemoryRiskStore;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use waf_common::HostConfig;
    use waf_common::tier::{CachePolicy, FailMode, RiskThresholds, TierPolicy};

    fn make_ctx() -> RequestCtx {
        RequestCtx {
            req_id: "test-123".to_string(),
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            client_port: 12345,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            port: 443,
            path: "/test".to_string(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: bytes::Bytes::new(),
            content_length: 0,
            is_tls: true,
            host_config: Arc::new(HostConfig {
                code: "test".to_string(),
                host: "example.com".to_string(),
                port: 443,
                ssl: true,
                guard_status: true,
                remote_host: "backend".to_string(),
                remote_port: 8080,
                remote_ip: None,
                cert_file: None,
                key_file: None,
                remarks: None,
                start_status: true,
                exclude_url_log: vec![],
                is_enable_load_balance: false,
                load_balance_strategy: waf_common::LoadBalanceStrategy::RoundRobin,
                defense_config: waf_common::DefenseConfig::default(),
                log_only_mode: false,
                block_page_template: None,
                preserve_host: true,
                strip_server_header: false,
                header_blocklist: vec![],
                internal_patterns: vec![],
                mask_token: "[REDACTED]".to_string(),
                body_mask_max_bytes: 1_000_000,
            }),
            geo: None,
            tier: waf_common::tier::Tier::CatchAll,
            tier_policy: Arc::new(TierPolicy {
                fail_mode: FailMode::Open,
                ddos_threshold_rps: 1000,
                cache_policy: CachePolicy::NoCache,
                risk_thresholds: RiskThresholds {
                    allow: 30,
                    challenge: 70,
                    block: 90,
                },
            }),
            cookies: HashMap::new(),
        }
    }

    fn make_scorer() -> Scorer<MemoryRiskStore> {
        let store = Arc::new(MemoryRiskStore::new());
        let cfg = RiskConfig {
            enabled: true,
            ..Default::default()
        };
        let swap = Arc::new(ArcSwap::from(Arc::new(cfg)));
        Scorer::new(store, swap)
    }

    #[tokio::test]
    async fn score_returns_allow_for_zero_score() {
        let scorer = make_scorer();
        let ctx = make_ctx();

        let result = scorer.score(&ctx, None, &[], 1000).await.unwrap();
        assert_eq!(result.score, 0);
        assert!(matches!(result.action, WafAction::Allow));
    }

    #[tokio::test]
    async fn score_disabled_returns_allow() {
        let store = Arc::new(MemoryRiskStore::new());
        let cfg = RiskConfig::default(); // enabled = false
        let swap = Arc::new(ArcSwap::from(Arc::new(cfg)));
        let scorer = Scorer::new(store, swap);
        let ctx = make_ctx();

        let result = scorer.score(&ctx, None, &[], 1000).await.unwrap();
        assert_eq!(result.score, 0);
        assert!(matches!(result.action, WafAction::Allow));
    }

    #[tokio::test]
    async fn score_accumulates_deltas() {
        use crate::risk::state::ContributorKind;

        let scorer = make_scorer();
        let ctx = make_ctx();

        let deltas = vec![Contributor::new(ContributorKind::Seed, 35, 1000)];
        let result = scorer.score(&ctx, None, &deltas, 1000).await.unwrap();

        assert_eq!(result.score, 35);
        assert!(matches!(result.action, WafAction::Challenge));
    }

    #[tokio::test]
    async fn score_blocks_at_threshold() {
        use crate::risk::state::ContributorKind;

        let scorer = make_scorer();
        let ctx = make_ctx();

        let deltas = vec![Contributor::new(ContributorKind::Seed, 95, 1000)];
        let result = scorer.score(&ctx, None, &deltas, 1000).await.unwrap();

        assert_eq!(result.score, 95);
        assert!(matches!(result.action, WafAction::Block { .. }));
    }

    #[tokio::test]
    async fn header_name_from_config() {
        let scorer = make_scorer();
        assert_eq!(scorer.header_name(), "X-WAF-Risk-Score");
    }
}
