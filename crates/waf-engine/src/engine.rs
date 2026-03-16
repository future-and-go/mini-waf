use std::sync::Arc;
use tracing::{debug, warn};
use uuid::Uuid;

use waf_common::{RequestCtx, WafAction, WafDecision};
use waf_storage::{
    models::{AttackLog, CreateSecurityEvent},
    Database,
};

use crate::block_page::render_block_page;
use crate::checker::{
    check_ip_blacklist, check_ip_whitelist, check_url_blacklist, check_url_whitelist, RuleStore,
};
use crate::checks::{
    BotCheck, CcCheck, Check, DirTraversalCheck, RceCheck, ScannerCheck, SqlInjectionCheck,
    XssCheck,
};

/// WAF engine configuration
#[derive(Debug, Clone, Default)]
pub struct WafEngineConfig {
    /// Whether to log allowed requests that matched whitelist rules
    pub log_whitelist_hits: bool,
}

/// Main WAF engine — runs all detection phases.
///
/// Phase 1-4  : IP / URL whitelist + blacklist (fast-path)
/// Phase 5-11 : Attack detection (CC, scanner, bot, SQLi, XSS, RCE, traversal)
pub struct WafEngine {
    pub store: Arc<RuleStore>,
    db: Arc<Database>,
    #[allow(dead_code)]
    config: WafEngineConfig,
    /// Dynamic checker pipeline (Phase 2 detectors).
    checkers: Vec<Box<dyn Check>>,
}

impl WafEngine {
    pub fn new(db: Arc<Database>, config: WafEngineConfig) -> Self {
        let store = Arc::new(RuleStore::new(Arc::clone(&db)));

        // Build the Phase 2 checker pipeline.
        // CC runs first to shed flood traffic before expensive pattern checks.
        let checkers: Vec<Box<dyn Check>> = vec![
            Box::new(CcCheck::new()),
            Box::new(ScannerCheck::new()),
            Box::new(BotCheck::new()),
            Box::new(SqlInjectionCheck::new()),
            Box::new(XssCheck::new()),
            Box::new(RceCheck::new()),
            Box::new(DirTraversalCheck::new()),
        ];

        Self {
            store,
            db,
            config,
            checkers,
        }
    }

    /// Reload all rules from the database
    pub async fn reload_rules(&self) -> anyhow::Result<()> {
        self.store.reload_all().await
    }

    /// Run the full WAF inspection pipeline.
    ///
    /// Returns the WAF decision. Callers should check `decision.is_allowed()`.
    pub async fn inspect(&self, ctx: &RequestCtx) -> WafDecision {
        // Skip WAF if guard is disabled for this host
        if !ctx.host_config.guard_status {
            return WafDecision::allow();
        }

        // ── Phase 1: IP Whitelist — allow immediately if matched ──────────────
        let ip_wl = check_ip_whitelist(ctx, &self.store);
        if let Some(ref result) = ip_wl.result {
            if matches!(ip_wl.action, WafAction::Allow)
                && result.phase == waf_common::Phase::IpWhitelist
            {
                debug!("Request allowed by IP whitelist: {}", ctx.client_ip);
                return ip_wl;
            }
        }

        // ── Phase 2: IP Blacklist — block if matched ───────────────────────────
        let ip_bl = check_ip_blacklist(ctx, &self.store);
        if !ip_bl.is_allowed() {
            self.log_attack(ctx, &ip_bl).await;
            return ip_bl;
        }

        // ── Phase 3: URL Whitelist — allow immediately if matched ──────────────
        if let Some(url_wl) = check_url_whitelist(ctx, &self.store) {
            debug!("Request allowed by URL whitelist: {}", ctx.path);
            return url_wl;
        }

        // ── Phase 4: URL Blacklist — block if matched ──────────────────────────
        let url_bl = check_url_blacklist(ctx, &self.store);
        if !url_bl.is_allowed() {
            self.log_attack(ctx, &url_bl).await;
            return url_bl;
        }

        // ── Phase 5-11: Attack detection pipeline ─────────────────────────────
        for checker in &self.checkers {
            if let Some(result) = checker.check(ctx) {
                let rule_name = result.rule_name.clone();

                let decision = if ctx.host_config.log_only_mode {
                    WafDecision {
                        action: WafAction::LogOnly,
                        result: Some(result),
                    }
                } else {
                    let body = render_block_page(ctx, &rule_name);
                    WafDecision::block(403, Some(body), result)
                };

                self.log_security_event(ctx, &decision).await;
                return decision;
            }
        }

        WafDecision::allow()
    }

    // ── Logging helpers ───────────────────────────────────────────────────────

    /// Log a Phase 1/2 event to the `attack_logs` table (fire-and-forget).
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
            query: if ctx.query.is_empty() {
                None
            } else {
                Some(ctx.query.clone())
            },
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

    /// Log a Phase 2 security event to the `security_events` table (fire-and-forget).
    async fn log_security_event(&self, ctx: &RequestCtx, decision: &WafDecision) {
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

        let event = CreateSecurityEvent {
            host_code: ctx.host_config.code.clone(),
            client_ip: ctx.client_ip.to_string(),
            method: ctx.method.clone(),
            path: ctx.path.clone(),
            rule_id: result.rule_id.clone(),
            rule_name: result.rule_name.clone(),
            action: action_str.to_string(),
            detail: Some(result.detail.clone()),
            geo_info: None,
        };

        let db = Arc::clone(&self.db);
        tokio::spawn(async move {
            if let Err(e) = db.create_security_event(event).await {
                warn!("Failed to log security event: {}", e);
            }
        });
    }
}
