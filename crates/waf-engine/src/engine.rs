use std::sync::Arc;
use tracing::{debug, warn};
use uuid::Uuid;

use waf_common::{RequestCtx, WafAction, WafDecision};
use waf_storage::{Database, models::AttackLog};

use crate::checker::{
    check_ip_blacklist, check_ip_whitelist, check_url_blacklist, check_url_whitelist, RuleStore,
};

/// WAF engine configuration
#[derive(Debug, Clone, Default)]
pub struct WafEngineConfig {
    /// Whether to log allowed requests that matched whitelist rules
    pub log_whitelist_hits: bool,
}

/// Main WAF engine — runs all detection phases
pub struct WafEngine {
    pub store: Arc<RuleStore>,
    db: Arc<Database>,
    #[allow(dead_code)]
    config: WafEngineConfig,
}

impl WafEngine {
    pub fn new(db: Arc<Database>, config: WafEngineConfig) -> Self {
        let store = Arc::new(RuleStore::new(Arc::clone(&db)));
        Self { store, db, config }
    }

    /// Reload all rules from the database
    pub async fn reload_rules(&self) -> anyhow::Result<()> {
        self.store.reload_all().await
    }

    /// Run the full WAF inspection pipeline
    ///
    /// Returns the WAF decision. Callers should check `decision.is_allowed()`.
    pub async fn inspect(&self, ctx: &RequestCtx) -> WafDecision {
        // Skip WAF if guard is disabled for this host
        if !ctx.host_config.guard_status {
            return WafDecision::allow();
        }

        // Phase 1: IP Whitelist — allow immediately if matched
        let ip_wl = check_ip_whitelist(ctx, &self.store);
        if let Some(ref result) = ip_wl.result {
            if matches!(ip_wl.action, WafAction::Allow) && result.phase == waf_common::Phase::IpWhitelist {
                debug!("Request allowed by IP whitelist: {}", ctx.client_ip);
                return ip_wl;
            }
        }

        // Phase 2: IP Blacklist — block if matched
        let ip_bl = check_ip_blacklist(ctx, &self.store);
        if !ip_bl.is_allowed() {
            self.log_attack(ctx, &ip_bl).await;
            return ip_bl;
        }

        // Phase 3: URL Whitelist — allow immediately if matched
        if let Some(url_wl) = check_url_whitelist(ctx, &self.store) {
            debug!("Request allowed by URL whitelist: {}", ctx.path);
            return url_wl;
        }

        // Phase 4: URL Blacklist — block if matched
        let url_bl = check_url_blacklist(ctx, &self.store);
        if !url_bl.is_allowed() {
            self.log_attack(ctx, &url_bl).await;
            return url_bl;
        }

        WafDecision::allow()
    }

    /// Log an attack event to the database (fire-and-forget)
    async fn log_attack(&self, ctx: &RequestCtx, decision: &WafDecision) {
        let result = match &decision.result {
            Some(r) => r,
            None => return,
        };

        let action_str = match &decision.action {
            WafAction::Block { .. } => "block",
            WafAction::Allow => "allow",
            WafAction::LogOnly => "log_only",
            WafAction::Redirect { .. } => "redirect",
        };

        let log = AttackLog {
            id: Uuid::new_v4(),
            host_code: ctx.host_config.code.clone(),
            host: ctx.host.clone(),
            client_ip: ctx.client_ip.to_string(),
            method: ctx.method.clone(),
            path: ctx.path.clone(),
            query: if ctx.query.is_empty() { None } else { Some(ctx.query.clone()) },
            rule_id: result.rule_id.clone(),
            rule_name: result.rule_name.clone(),
            action: action_str.to_string(),
            phase: result.phase.to_string(),
            detail: Some(result.detail.clone()),
            request_headers: None,
            created_at: chrono::Utc::now(),
        };

        let db = Arc::clone(&self.db);
        tokio::spawn(async move {
            if let Err(e) = db.create_attack_log(log).await {
                warn!("Failed to log attack event: {}", e);
            }
        });
    }
}
