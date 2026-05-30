//! FR-025 Scorer orchestrator.
//!
//! Builds `RiskKey` from request context, calls store, applies threshold gate,
//! sets `X-WAF-Risk-Score` header, returns `WafAction`.
//!
//! Phase 5 adds L2 detectors (anomaly + velocity) evaluated inline.
//! Phase 6 adds canary honeypot layer (FR-028) for scanner detection.
//! Phase 8 adds challenge credit verification (FR-006 wiring).

use std::sync::Arc;

use arc_swap::ArcSwap;
use tracing::info;

use waf_common::{RequestCtx, WafAction};

use crate::device_fp::types::FpKey;
use crate::risk::anomaly::{AnomalyCtx, AnomalyLayer};
use crate::risk::canary::CanaryLayer;
use crate::risk::challenge_credit::{ChallengeVerifier, VerifyOutcome};
use crate::risk::config::RiskConfig;
use crate::risk::key::{RiskKey, SessionId};
use crate::risk::seed::{SeedLayer, SeedVerdict};
use crate::risk::state::{Contributor, ContributorKind, CreditOutcome};
use crate::risk::store::RiskStore;
use crate::risk::threshold::decide;
use crate::risk::velocity::{TxEndpoint, VelocityLayer};

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
/// Phase 5 adds L2 detectors: anomaly layer and velocity layer.
/// Phase 6 adds canary honeypot layer (FR-028).
/// Phase 8 adds challenge credit verifier (FR-006).
pub struct Scorer<S: RiskStore> {
    store: Arc<S>,
    cfg: Arc<ArcSwap<RiskConfig>>,
    seed: Option<Arc<SeedLayer>>,
    /// FR-028 canary honeypot layer for scanner detection.
    pub canary: Option<Arc<CanaryLayer>>,
    /// FR-006 challenge credit verifier.
    challenge_verifier: Option<Arc<ChallengeVerifier>>,
    /// L2 anomaly detection layer (JA4↔UA mismatch, XFF, header sanity).
    anomaly: AnomalyLayer,
    /// L2 velocity detection layer (sliding window, sequence FSM).
    velocity: VelocityLayer,
}

impl<S: RiskStore> Scorer<S> {
    /// Create a new scorer with the given store and config.
    #[must_use]
    pub fn new(store: Arc<S>, cfg: Arc<ArcSwap<RiskConfig>>) -> Self {
        Self {
            store,
            cfg,
            seed: None,
            canary: None,
            challenge_verifier: None,
            anomaly: AnomalyLayer::new(),
            velocity: VelocityLayer::with_defaults(),
        }
    }

    /// Create a scorer with seed layer.
    #[must_use]
    pub fn with_seed(store: Arc<S>, cfg: Arc<ArcSwap<RiskConfig>>, seed: Arc<SeedLayer>) -> Self {
        Self {
            store,
            cfg,
            seed: Some(seed),
            canary: None,
            challenge_verifier: None,
            anomaly: AnomalyLayer::new(),
            velocity: VelocityLayer::with_defaults(),
        }
    }

    /// Create a scorer with custom velocity threshold.
    #[must_use]
    pub fn with_velocity_threshold(store: Arc<S>, cfg: Arc<ArcSwap<RiskConfig>>, threshold: u32) -> Self {
        Self {
            store,
            cfg,
            seed: None,
            canary: None,
            challenge_verifier: None,
            anomaly: AnomalyLayer::new(),
            velocity: VelocityLayer::new(threshold),
        }
    }

    /// Set the seed layer.
    pub fn set_seed(&mut self, seed: Arc<SeedLayer>) {
        self.seed = Some(seed);
    }

    /// Set the canary layer.
    pub fn set_canary(&mut self, canary: Arc<CanaryLayer>) {
        self.canary = Some(canary);
    }

    /// Set the challenge credit verifier.
    pub fn set_challenge_verifier(&mut self, verifier: Arc<ChallengeVerifier>) {
        self.challenge_verifier = Some(verifier);
    }

    /// Load the current config snapshot.
    #[must_use]
    pub fn config(&self) -> Arc<RiskConfig> {
        self.cfg.load_full()
    }

    /// Score a request and return the result.
    ///
    /// # Arguments
    /// * `ctx` - The request context (contains IP, tier, cookies, headers)
    /// * `fp_key` - Optional device fingerprint key
    /// * `sync_deltas` - Risk deltas from earlier checks (e.g., rule matches)
    /// * `tx_endpoint` - Optional transaction endpoint for sequence FSM
    /// * `now_ms` - Current timestamp in milliseconds
    pub async fn score(
        &self,
        ctx: &RequestCtx,
        fp_key: Option<&FpKey>,
        sync_deltas: &[Contributor],
        tx_endpoint: Option<TxEndpoint>,
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

        // L0 seed layer evaluation FIRST — whitelist short-circuits everything
        if let Some(ref seed) = self.seed
            && cfg.seed.enabled
        {
            match seed.evaluate(ctx.client_ip) {
                SeedVerdict::Whitelisted => {
                    return Ok(ScorerResult {
                        action: WafAction::Allow,
                        score: 0,
                        is_new: false,
                    });
                }
                SeedVerdict::Score { delta, kind } => {
                    let seed_contrib = Contributor::new(ContributorKind::Seed(kind), i16::from(delta), now_ms);
                    let mut all_deltas = vec![seed_contrib];
                    all_deltas.extend_from_slice(sync_deltas);
                    return self
                        .score_with_l2(ctx, fp_key, &all_deltas, tx_endpoint, now_ms, &cfg)
                        .await;
                }
                SeedVerdict::None => {}
            }
        }

        // FR-028 Canary honeypot check — AFTER whitelist, BEFORE other layers
        // On canary hit: force_max + return Block immediately
        if let Some(ref canary) = self.canary
            && cfg.canary.enabled
            && canary.check_and_ban(&ctx.path, ctx.client_ip, now_ms)
        {
            // Pin score to 100 and add to ban table
            let until_ms = now_ms.saturating_add(canary.ban_ttl_ms());
            if let Err(e) = self.force_max(ctx, fp_key, until_ms, now_ms).await {
                tracing::warn!(error = %e, "canary: force_max failed");
            }

            info!(
                path = %ctx.path,
                client_ip = %ctx.client_ip,
                "canary honeypot: blocking scanner"
            );

            return Ok(ScorerResult {
                action: WafAction::Block {
                    status: 403,
                    body: Some("canary_honeypot".to_string()),
                },
                score: 100,
                is_new: false,
            });
        }

        self.score_with_l2(ctx, fp_key, sync_deltas, tx_endpoint, now_ms, &cfg)
            .await
    }

    /// Internal scoring with L2 layer evaluation.
    async fn score_with_l2(
        &self,
        ctx: &RequestCtx,
        fp_key: Option<&FpKey>,
        deltas: &[Contributor],
        tx_endpoint: Option<TxEndpoint>,
        now_ms: i64,
        cfg: &RiskConfig,
    ) -> anyhow::Result<ScorerResult> {
        let key = Self::build_key(ctx, fp_key, cfg);

        if key.is_empty() {
            return Ok(ScorerResult {
                action: WafAction::Allow,
                score: 0,
                is_new: true,
            });
        }

        // Collect all deltas: input + L2 anomaly + L2 velocity
        let mut all_deltas = deltas.to_vec();

        // L2 Anomaly layer: JA4↔UA mismatch, XFF chain, header sanity
        let ja4 = fp_key
            .and_then(|k| k.ja4.as_ref())
            .map(crate::device_fp::types::FingerprintValue::as_str);
        let user_agent = ctx.headers.get("user-agent").map_or("", String::as_str);
        let xff = ctx.headers.get("x-forwarded-for").map(String::as_str);
        let anomaly_ctx = AnomalyCtx::new(ja4, user_agent, xff, &ctx.headers);
        let anomaly_deltas = self.anomaly.evaluate(&anomaly_ctx, now_ms);
        all_deltas.extend(anomaly_deltas);

        // L2 Velocity layer: sliding window + sequence FSM
        let velocity_deltas = self.velocity.evaluate(&key, tx_endpoint, now_ms);
        all_deltas.extend(velocity_deltas);

        // FR-006 Challenge credit verification
        if let Some(credit_delta) = self.evaluate_challenge_credit(ctx, &key, now_ms, cfg).await {
            all_deltas.push(credit_delta);
        }

        // Apply to store (decay happens inside store.apply before fold)
        let result = self.store.apply(&key, &all_deltas, now_ms).await?;
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

    /// Evaluate challenge credit header and return contributor if present.
    async fn evaluate_challenge_credit(
        &self,
        ctx: &RequestCtx,
        key: &RiskKey,
        now_ms: i64,
        cfg: &RiskConfig,
    ) -> Option<Contributor> {
        if !cfg.challenge.enabled {
            return None;
        }

        let verifier = self.challenge_verifier.as_ref()?;
        let credit_header = ctx.headers.get(&cfg.challenge.header_name)?;

        // Resolve owner_id from RiskKey for binding check
        let owner_id = key.owner_id();

        let outcome = verifier.verify(credit_header, &owner_id, now_ms).await;

        let (delta, credit_outcome) = match outcome {
            VerifyOutcome::Valid { nonce } => {
                tracing::debug!(nonce = %nonce, "challenge credit: valid token applied");
                (cfg.challenge.valid_delta, CreditOutcome::Valid)
            }
            VerifyOutcome::Invalid(reason) => {
                tracing::debug!(reason = %reason, "challenge credit: invalid token");
                (cfg.challenge.invalid_delta, CreditOutcome::Invalid)
            }
            VerifyOutcome::Replay => (cfg.challenge.replay_delta, CreditOutcome::Replay),
            VerifyOutcome::Expired => {
                tracing::debug!("challenge credit: expired token");
                (cfg.challenge.expired_delta, CreditOutcome::Expired)
            }
        };

        Some(Contributor::new(
            ContributorKind::ChallengeCredit(credit_outcome),
            delta,
            now_ms,
        ))
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
                ..Default::default()
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
            device_fp: None,
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

        let result = scorer.score(&ctx, None, &[], None, 1000).await.unwrap();
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

        let result = scorer.score(&ctx, None, &[], None, 1000).await.unwrap();
        assert_eq!(result.score, 0);
        assert!(matches!(result.action, WafAction::Allow));
    }

    #[tokio::test]
    async fn score_accumulates_deltas() {
        use crate::risk::state::{ContributorKind, SeedKind};

        let scorer = make_scorer();
        let ctx = make_ctx();

        let deltas = vec![Contributor::new(ContributorKind::Seed(SeedKind::Generic), 35, 1000)];
        let result = scorer.score(&ctx, None, &deltas, None, 1000).await.unwrap();

        assert_eq!(result.score, 35);
        assert!(matches!(result.action, WafAction::Challenge));
    }

    #[tokio::test]
    async fn score_blocks_at_threshold() {
        use crate::risk::state::{ContributorKind, SeedKind};

        let scorer = make_scorer();
        let ctx = make_ctx();

        let deltas = vec![Contributor::new(ContributorKind::Seed(SeedKind::Generic), 95, 1000)];
        let result = scorer.score(&ctx, None, &deltas, None, 1000).await.unwrap();

        assert_eq!(result.score, 95);
        assert!(matches!(result.action, WafAction::Block { .. }));
    }

    #[tokio::test]
    async fn header_name_from_config() {
        let scorer = make_scorer();
        assert_eq!(scorer.header_name(), "X-WAF-Risk-Score");
    }
}
