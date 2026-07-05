use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use arc_swap::ArcSwap;
use tracing::{debug, info, warn};
use uuid::Uuid;

use waf_common::{DetectionResult, InteropMode, RequestCtx, RuleAction, WafAction, WafDecision};
use waf_storage::{
    Database,
    models::{AttackLog, CreateSecurityEvent},
};

use crate::block_page::render_block_page;
use crate::checker::{RuleStore, check_ip_blacklist, check_ip_whitelist, check_url_blacklist, check_url_whitelist};
use crate::interop::ModeRegistry;
use crate::interop::checker_feature_map::phase_feature_identity;
use waf_common::config::SqliScanConfig;

use crate::checks::ddos::action::{BanAction, CombinedAction};
use crate::checks::ddos::detector::PerIpDetector;
use crate::checks::ddos::reload::DEFAULT_DEBOUNCE_MS as DDOS_DEBOUNCE_MS;
use crate::checks::ddos::store::MemoryCounterStore as DdosMemoryStore;
use crate::checks::ddos::{
    DdosCheck, DdosConfig, DdosFileConfig, DdosMetrics, DdosReloader, DynamicBanTable, OverloadGuard,
};
use crate::checks::geo_reload::DEFAULT_DEBOUNCE_MS as GEO_DEBOUNCE_MS;
use crate::checks::rate_limit::reload::{DEFAULT_DEBOUNCE_MS as RL_DEBOUNCE_MS, RateLimitReloader};
use crate::checks::rate_limit::store::MemoryStore as RlMemoryStore;
use crate::checks::rate_limit::{RateLimitFileConfig, store::RateLimitStore};
use crate::checks::tx_velocity::{
    TxStore, TxVelocityCheck, TxVelocityConfig, TxVelocityFileConfig, TxVelocityReloader,
};
use crate::checks::{
    AntiHotlinkCheck, BotCheck, BruteForceCheck, Check, DirTraversalCheck, GeoCheck, HeaderInjectionCheck, OWASPCheck,
    RateLimitCheck, RateLimitConfig, RceCheck, RequestBodyAbuseCheck, ScannerCheck, SensitiveCheck, SqlInjectionCheck,
    SsrfCheck, XssCheck,
};
use crate::community::{CommunityChecker, CommunityReporter, RequestInfo};
use crate::crowdsec::{AppSecClient, AppSecResult, CrowdSecChecker, appsec_to_detection};
use crate::geoip::GeoIpService;
use crate::logging::{AuditEvent, AuditEventType, AuditSender, DbBatchWriter, DbLogEvent};
use crate::rules::custom_file_loader::CustomRuleFileWatcher;
use crate::rules::engine::{CustomRulesEngine, from_db_rule};

use crate::risk::canary::{CanaryLayer, DEFAULT_CANARY_BAN_TTL_SECS};
use crate::risk::config::RiskConfig;
use crate::risk::reload::{DEFAULT_DEBOUNCE_MS as RISK_DEBOUNCE_MS, RiskReloader};
use crate::risk::scorer::{Scorer, ScorerResult};
use crate::risk::store::{MemoryRiskStore, RiskStore};

/// WAF engine configuration
#[derive(Debug, Clone, Default)]
pub struct WafEngineConfig {
    /// Whether to log allowed requests that matched whitelist rules
    pub log_whitelist_hits: bool,
}

/// Borrowed request identity for [`WafEngine::emit_minimal_audit_stub`], used on
/// egress paths that have no `RequestCtx` to source these fields from.
pub struct MinimalAuditStub<'a> {
    pub req_id: &'a str,
    pub event_type: AuditEventType,
    pub host: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub peer_ip: &'a str,
    pub action: &'static str,
    pub detail: &'a str,
}

/// Main WAF engine — runs all detection phases.
///
/// Phase 1-4  : IP / URL whitelist + blacklist (fast-path)
/// Phase 16   : `CrowdSec` bouncer (cache lookup — runs early for efficiency)
/// Phase 5-11 : Attack detection (CC, scanner, bot, `SQLi`, XSS, RCE, traversal)
/// Phase 16b  : `CrowdSec` `AppSec` (async HTTP check — runs after local detectors)
/// Phase 12   : Custom rules engine (Rhai scripting)
/// Phase 13   : OWASP CRS subset
/// Phase 14   : Sensitive data detection
/// Phase 15   : Anti-hotlinking
pub struct WafEngine {
    pub store: Arc<RuleStore>,
    pub custom_rules: Arc<CustomRulesEngine>,
    pub sensitive: Arc<SensitiveCheck>,
    pub hotlink: Arc<AntiHotlinkCheck>,
    db: Arc<Database>,
    #[allow(dead_code)]
    config: WafEngineConfig,
    /// Dynamic checker pipeline (Phase 5-11 detectors).
    checkers: Vec<Box<dyn Check>>,
    owasp: Arc<OWASPCheck>,
    /// GeoIP-based access control check (Phase 17).
    geo_check: Arc<GeoCheck>,
    /// SQL injection checker (stored separately for config hot-reload)
    sqli_check: Arc<SqlInjectionCheck>,
    // ── Phase 6: `CrowdSec` ───────────────────────────────────────────────────
    /// Bouncer checker (set once after engine construction via `set_crowdsec`)
    crowdsec_checker: OnceLock<Arc<CrowdSecChecker>>,
    /// `AppSec` client (set once after engine construction via `set_crowdsec`)
    appsec_client: OnceLock<Arc<AppSecClient>>,
    // ── Community ──────────────────────────────────────────────────────────
    /// Community blocklist checker (set once after engine construction via `set_community`)
    community_checker: OnceLock<Arc<CommunityChecker>>,
    /// Community signal reporter for pushing detections (set once via `set_community_reporter`)
    community_reporter: OnceLock<Arc<CommunityReporter>>,
    // ── `GeoIP` ────────────────────────────────────────────────────────────────
    /// `GeoIP` lookup service (set once after engine construction via `set_geoip`)
    geoip: OnceLock<Arc<GeoIpService>>,
    // ── FR-003 file-based custom rules ────────────────────────────────────────
    /// Root rules directory; `<rules_dir>/custom/*.yaml` is scanned during
    /// `reload_rules`. Set once via `set_rules_dir`; falls back to `./rules`.
    rules_dir: OnceLock<PathBuf>,
    /// File watcher for `<rules_dir>/custom/*.yaml` (FR-003 hot-reload).
    /// Set lazily via `start_file_watcher`; held to keep the OS watch alive.
    file_watcher: OnceLock<CustomRuleFileWatcher>,
    // ── FR-004 rate-limit (phase-07) ─────────────────────────────────────────
    /// Hot-reloadable rate-limit config snapshot. Shared with the
    /// `RateLimitCheck` registered in `checkers`.
    rate_limit_cfg: Arc<ArcSwap<RateLimitConfig>>,
    /// File watcher for `configs/rate-limit.yaml`. Lazy via
    /// `start_rate_limit_watcher`; held to keep the OS watch alive.
    rate_limit_reloader: OnceLock<RateLimitReloader>,
    // ── FR-012 tx-velocity (phase-03) ────────────────────────────────────────
    /// Hot-reloadable tx-velocity config snapshot. Shared with the
    /// `TxVelocityCheck` and `TxStore` registered in `checkers`.
    tx_velocity_cfg: Arc<ArcSwap<TxVelocityConfig>>,
    /// In-memory transaction store for velocity tracking.
    /// Kept alive for `TxVelocityCheck`; not accessed directly after construction.
    #[allow(dead_code)]
    tx_velocity_store: Arc<TxStore>,
    /// File watcher for `configs/tx-velocity.yaml`. Lazy via
    /// `start_tx_velocity_watcher`; held to keep the OS watch alive.
    tx_velocity_reloader: OnceLock<TxVelocityReloader>,
    // ── FR-005 ddos-protection (phase-07) ────────────────────────────────────
    /// Hot-reloadable `DDoS` config snapshot.
    ddos_cfg: Arc<ArcSwap<DdosConfig>>,
    /// `DdosCheck` instance for pipeline integration.
    ddos_check: Arc<DdosCheck>,
    /// File watcher for `configs/ddos.yaml`. Lazy via
    /// `start_ddos_watcher`; held to keep the OS watch alive.
    ddos_reloader: OnceLock<DdosReloader>,
    /// File watcher for `configs/geo-rules.yaml`. Lazy via
    /// `start_geo_watcher`; held to keep the OS watch alive.
    geo_reloader: OnceLock<crate::checks::GeoReloader>,
    // ── Audit file sink sender ────────────────────────────────────────────────
    /// Structured audit-event sink. `None` until [`set_audit_sender`] is
    /// called by the binary boot path.  When set, every non-Allow decision
    /// from `inspect()` is written to the JSONL audit file sink.
    audit_sender: OnceLock<Arc<AuditSender>>,
    // ── Phase 03: Batched DB log writer ──────────────────────────────────────
    /// Bounded MPSC batch writer for `attack_logs` and `security_events` tables.
    /// Replaces per-detection `tokio::spawn` with a single `try_send`.
    db_batch_writer: OnceLock<DbBatchWriter>,
    // ── Interop: per-feature mode resolution ────────────────────────────────
    mode_registry: OnceLock<ModeRegistry>,
    /// Hot-swappable risk-scoring config. Default `RiskConfig` has
    /// `enabled = false`, so `Scorer.score()` returns score=0 / Allow until
    /// a real config is loaded via [`Self::replace_risk_config`].
    risk_cfg: Arc<ArcSwap<RiskConfig>>,
    /// Risk scorer threaded into `inspect()`. Construction installs a
    /// memory-backed scorer so the engine stays infrastructure-free;
    /// [`Self::start_risk_watcher`] swaps in a store built from
    /// `RiskConfig.store` (memory with purge loop, or redis). Provides the
    /// `decision.risk_score` attached to every WAF decision and drives
    /// FR-025 enforcement: a scorer Block/Challenge escalates a plain-Allow
    /// pipeline decision (see [`Self::inspect`]).
    scorer: ArcSwap<Scorer<dyn RiskStore>>,
    /// Hot-reload watcher handle for `configs/risk.yaml` (guards double-start).
    risk_reloader: OnceLock<RiskReloader>,
    /// FR-028 canary honeypot layer installed on the scorer. Bound to the
    /// `DDoS` [`DynamicBanTable`] so canary hits IP-ban at the `DDoS` phase on
    /// subsequent requests. Paths and ban TTL follow `RiskConfig.canary`
    /// via [`Self::replace_risk_config`].
    risk_canary: Arc<CanaryLayer>,
    // ── FR-007/FR-042 relay-intel feed metadata (D3) ─────────────────────────
    /// Threat-intel feed metadata (Tor / ASN / datacenter), loaded from
    /// `configs/relay.yaml` at startup via [`Self::load_relay_feeds`]. Empty
    /// until loaded. Surfaced read-only by `GET /api/threat-intel/feeds`.
    relay_feeds: ArcSwap<Vec<crate::relay::FeedMeta>>,
}

/// Whether [`WafEngine::inspect_pipeline`] exited on one of the pre-scoring
/// fast paths (guard disabled, IP/URL whitelist or blacklist). Fast-path
/// requests skip the risk scorer entirely — no store write, no scoring cost.
enum FastPath {
    Hit,
    Miss,
}

impl WafEngine {
    pub fn new(db: Arc<Database>, config: WafEngineConfig) -> Self {
        Self::with_sqli_config(db, config, SqliScanConfig::default())
    }

    pub fn with_sqli_config(db: Arc<Database>, config: WafEngineConfig, sqli_cfg: SqliScanConfig) -> Self {
        let store = Arc::new(RuleStore::new(Arc::clone(&db)));
        let custom_rules = Arc::new(CustomRulesEngine::new());
        let sensitive = Arc::new(SensitiveCheck::new());
        let hotlink = Arc::new(AntiHotlinkCheck::new());
        let owasp = Arc::new(OWASPCheck::new());
        let geo_check = Arc::new(GeoCheck::new());
        let sqli_check = Arc::new(SqlInjectionCheck::with_config(sqli_cfg));

        // Build the Phase 5-11 checker pipeline (SQLi handled separately for hot-reload).
        // FR-004 RateLimitCheck runs first to shed flood traffic before expensive
        // pattern checks. Inert until `start_rate_limit_watcher` loads tier config.
        // FR-014..020 checks register here so each downstream FR PR only swaps
        // its own check file (zero shared-edit conflicts).
        let rl_store: Arc<dyn RateLimitStore> = Arc::new(RlMemoryStore::new());
        let rate_limit_cfg = Arc::new(ArcSwap::from(Arc::new(RateLimitConfig::default())));

        // FR-012 TxVelocityCheck: signal-only, records events and emits risk signals.
        // Runs after rate-limit (shed flood traffic first), before pattern checks.
        // Inert until `start_tx_velocity_watcher` loads config.
        let tx_velocity_cfg = Arc::new(ArcSwap::from(Arc::new(TxVelocityConfig::default())));
        let tx_velocity_store = Arc::new(TxStore::new(Arc::clone(&tx_velocity_cfg)));

        // FR-005 DdosCheck: burst detection and banning.
        // Runs BEFORE rate-limit in the pipeline (separate from checkers vec).
        // Inert until `start_ddos_watcher` loads config.
        let ddos_cfg = Arc::new(ArcSwap::from(Arc::new(DdosConfig::default())));
        // Reuse rate-limit store for per-IP detection (same token bucket algorithm)
        let ddos_rl_store: Arc<dyn RateLimitStore> = Arc::new(RlMemoryStore::new());
        // Separate counter store for offense tracking (ban escalation)
        let ddos_counter_store: Arc<dyn crate::checks::ddos::store::CounterStore> =
            Arc::new(DdosMemoryStore::new(100_000, 60));
        let ddos_ban_table = Arc::new(DynamicBanTable::new());
        let ddos_guard = Arc::new(OverloadGuard::default());
        let ddos_metrics = Arc::new(DdosMetrics::new());

        // Build detectors (cheap-first order)
        let ddos_detectors: Vec<Box<dyn crate::checks::ddos::detector::Detector>> =
            vec![Box::new(PerIpDetector::new(ddos_rl_store))];

        // Build action executors (ban only — risk bump requires FR-010 aggregator)
        let ddos_ban_action = BanAction::with_defaults(Arc::clone(&ddos_ban_table), ddos_counter_store);
        let ddos_action = Arc::new(CombinedAction::new(vec![Box::new(ddos_ban_action)]));

        let ddos_check = Arc::new(DdosCheck::new(
            Arc::clone(&ddos_cfg),
            ddos_detectors,
            ddos_action,
            Arc::clone(&ddos_guard),
            Arc::clone(&ddos_ban_table),
            Arc::clone(&ddos_metrics),
        ));

        let checkers: Vec<Box<dyn Check>> = vec![
            Box::new(RateLimitCheck::new(rl_store, Arc::clone(&rate_limit_cfg))),
            Box::new(TxVelocityCheck::new(
                Arc::clone(&tx_velocity_cfg),
                Arc::clone(&tx_velocity_store),
            )),
            Box::new(ScannerCheck::new()),
            Box::new(BotCheck::new()),
            Box::new(XssCheck::new()),
            Box::new(RceCheck::new()),
            Box::new(DirTraversalCheck::new()),
            Box::new(SsrfCheck::new()),
            Box::new(HeaderInjectionCheck::new()),
            Box::new(BruteForceCheck::new()),
            Box::new(RequestBodyAbuseCheck::new()),
        ];

        // Risk scorer with in-memory store and default (disabled) config.
        // Operators that want real scoring call `replace_risk_config`.
        let risk_cfg = Arc::new(ArcSwap::from(Arc::new(RiskConfig::default())));
        let risk_store: Arc<dyn RiskStore> = Arc::new(MemoryRiskStore::new());
        // FR-028 canary layer bound to the DDoS ban table: a canary hit bans
        // the IP so follow-up requests block at the DDoS phase. Paths stay
        // empty (inert) until `replace_risk_config` loads them.
        let risk_canary = Arc::new(CanaryLayer::with_ban_table(
            Vec::new(),
            Arc::clone(ddos_check.ban_table()),
            DEFAULT_CANARY_BAN_TTL_SECS,
        ));
        let mut scorer = Scorer::new(risk_store, Arc::clone(&risk_cfg));
        scorer.set_canary(Arc::clone(&risk_canary));
        let scorer = ArcSwap::from_pointee(scorer);

        Self {
            store,
            custom_rules,
            sensitive,
            hotlink,
            db,
            config,
            checkers,
            owasp,
            geo_check,
            sqli_check,
            crowdsec_checker: OnceLock::new(),
            appsec_client: OnceLock::new(),
            community_checker: OnceLock::new(),
            community_reporter: OnceLock::new(),
            geoip: OnceLock::new(),
            rules_dir: OnceLock::new(),
            file_watcher: OnceLock::new(),
            rate_limit_cfg,
            rate_limit_reloader: OnceLock::new(),
            tx_velocity_cfg,
            tx_velocity_store,
            tx_velocity_reloader: OnceLock::new(),
            ddos_cfg,
            ddos_check,
            ddos_reloader: OnceLock::new(),
            geo_reloader: OnceLock::new(),
            audit_sender: OnceLock::new(),
            db_batch_writer: OnceLock::new(),
            mode_registry: OnceLock::new(),
            risk_cfg,
            scorer,
            risk_reloader: OnceLock::new(),
            risk_canary,
            relay_feeds: ArcSwap::from_pointee(Vec::new()),
        }
    }

    /// Hot-swap the risk-scoring config snapshot.
    ///
    /// `RiskConfig::default()` has `enabled = false`, so the scorer no-ops
    /// (score=0) until a real config is loaded. Operators wire production
    /// scoring via this entry point; tests use it to enable scoring on a
    /// per-test basis.
    pub fn replace_risk_config(&self, cfg: RiskConfig) {
        // Keep the canary layer in sync with the config: path set and ban TTL
        // are both hot-reloadable. The TTL governs the DDoS-table ban and the
        // force_max score pin (`CanaryLayer::ban_ttl_ms`).
        self.risk_canary.reload(cfg.canary.paths.clone());
        self.risk_canary.set_ban_ttl_secs(cfg.canary.ban_ttl_secs);
        self.risk_cfg.store(Arc::new(cfg));
    }

    /// Build a risk store from `RiskConfig.store`. Fail-soft: any redis
    /// failure (feature absent, connect/ping error) falls back to the
    /// in-memory store so the gateway never refuses to start.
    #[cfg_attr(not(feature = "redis-store"), allow(clippy::unused_async))]
    async fn build_risk_store(cfg: &RiskConfig) -> Arc<dyn RiskStore> {
        if cfg.store.backend == "redis" {
            #[cfg(feature = "redis-store")]
            {
                let runtime_cfg = cfg.store.redis.to_runtime_config(cfg.ttl_secs, cfg.decay.clone());
                // Bound the initial connect: ConnectionManager retries with
                // backoff internally, which can stall startup for minutes
                // when the host silently drops packets. Fail-soft needs a
                // fast answer.
                let connect = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    crate::risk::store::RedisRiskStore::new(runtime_cfg),
                );
                match connect.await {
                    Ok(Ok(store)) => {
                        info!("risk: redis store connected");
                        return Arc::new(store);
                    }
                    Ok(Err(e)) => {
                        warn!(error = %e, "risk: redis store connect failed; falling back to memory store");
                    }
                    Err(_) => {
                        warn!("risk: redis store connect timed out; falling back to memory store");
                    }
                }
            }
            #[cfg(not(feature = "redis-store"))]
            warn!("risk: store.backend=redis requires the redis-store build feature; using memory store");
        }
        let store = Arc::new(MemoryRiskStore::with_decay(cfg.decay.clone()));
        // The purge loop needs the concrete `Arc<MemoryRiskStore>`; start it
        // before the Arc is unsized to `Arc<dyn RiskStore>`.
        let ttl_ms = i64::try_from(cfg.ttl_secs.saturating_mul(1000)).unwrap_or(i64::MAX);
        store.start_purge_loop(ttl_ms, cfg.gc_interval_secs, Arc::new(crate::time::SystemClock));
        store
    }

    /// Build a scorer over `store` sharing the engine's config snapshot and
    /// canary layer (the canary must be re-attached on every scorer rebuild
    /// or honeypot hits stop pinning scores).
    fn build_scorer(&self, store: Arc<dyn RiskStore>) -> Scorer<dyn RiskStore> {
        let mut scorer = Scorer::new(store, Arc::clone(&self.risk_cfg));
        scorer.set_canary(Arc::clone(&self.risk_canary));
        scorer
    }

    /// Load `configs/risk.yaml` once, build the configured store, and start
    /// the hot-reload watcher.
    ///
    /// Bad YAML or a missing file logs a warning and leaves risk scoring at
    /// defaults (disabled, memory store) — the gateway never refuses to start
    /// because of a risk config issue. The store backend is start-time only:
    /// reloads swap the config snapshot (and resync the canary layer) but a
    /// `store.backend` change logs a warning and keeps the active store.
    pub async fn start_risk_watcher(&self, path: &Path) {
        if self.risk_reloader.get().is_some() {
            return;
        }
        let mut active_backend = "memory".to_string();
        match RiskConfig::from_path(path) {
            Ok(cfg) => {
                let store = Self::build_risk_store(&cfg).await;
                self.scorer.store(Arc::new(self.build_scorer(store)));
                active_backend.clone_from(&cfg.store.backend);
                self.replace_risk_config((*cfg).clone());
                info!(file = %path.display(), backend = %active_backend, "risk: initial config loaded");
            }
            Err(e) => {
                warn!(file = %path.display(), error = %e, "risk: initial load failed; risk scoring stays disabled");
            }
        }
        let canary = Arc::clone(&self.risk_canary);
        let risk_cfg = Arc::clone(&self.risk_cfg);
        let result = RiskReloader::start(path.to_path_buf(), RISK_DEBOUNCE_MS, move |cfg| {
            if cfg.store.backend != active_backend {
                warn!(
                    active = %active_backend,
                    requested = %cfg.store.backend,
                    "risk: store backend change requires restart; keeping active store"
                );
            }
            // Same semantics as `replace_risk_config`: canary paths + ban TTL
            // resync before the snapshot swap.
            canary.reload(cfg.canary.paths.clone());
            canary.set_ban_ttl_secs(cfg.canary.ban_ttl_secs);
            risk_cfg.store(cfg);
        });
        match result {
            Ok(r) => {
                let _ = self.risk_reloader.set(r);
            }
            Err(e) => warn!(
                file = %path.display(),
                error = %e,
                "risk: hot-reload watcher failed to start; running without hot-reload"
            ),
        }
    }

    /// Admin API: remove an actor's risk state (all axes reachable from the
    /// IP). Returns `true` if state existed and was removed.
    pub async fn risk_clear_actor(&self, ip: std::net::IpAddr) -> anyhow::Result<bool> {
        let scorer = self.scorer.load_full();
        let key = crate::risk::key::RiskKey::from_ip(ip);
        scorer.store().clear(&key).await
    }

    /// Admin API: credit (reduce) an actor's risk score by `amount` points.
    /// Returns the post-credit clamped score.
    pub async fn risk_credit_actor(&self, ip: std::net::IpAddr, amount: i16) -> anyhow::Result<u8> {
        use crate::risk::state::{Contributor, ContributorKind};

        let now_ms = chrono::Utc::now().timestamp_millis();
        let credit = Contributor::new(ContributorKind::AdminCredit, -amount.abs(), now_ms);
        let scorer = self.scorer.load_full();
        let result = scorer
            .store()
            .apply(&crate::risk::key::RiskKey::from_ip(ip), &[credit], now_ms)
            .await?;
        Ok(result.state.clamped_score)
    }

    /// Load `configs/rate-limit.yaml` once and start the hot-reload watcher.
    ///
    /// Bad YAML or a missing file logs a warning and leaves the subsystem
    /// inert (default empty config) — the gateway never refuses to start
    /// because of a rate-limit config issue.
    pub fn start_rate_limit_watcher(&self, path: &Path) {
        if self.rate_limit_reloader.get().is_some() {
            return;
        }
        match RateLimitFileConfig::from_path(path) {
            Ok(cfg) => {
                self.rate_limit_cfg.store(cfg);
                info!(file = %path.display(), "rate_limit: initial config loaded");
            }
            Err(e) => {
                warn!(file = %path.display(), error = %e, "rate_limit: initial load failed; using empty config");
            }
        }
        match RateLimitReloader::start(path.to_path_buf(), Arc::clone(&self.rate_limit_cfg), RL_DEBOUNCE_MS) {
            Ok(r) => {
                let _ = self.rate_limit_reloader.set(r);
            }
            Err(e) => warn!(
                file = %path.display(),
                error = %e,
                "rate_limit: hot-reload watcher failed to start; running without hot-reload"
            ),
        }
    }

    /// Test/admin hook: replace the rate-limit config snapshot directly.
    /// Used by integration tests; production paths go through the file watcher.
    #[cfg(test)]
    pub fn replace_rate_limit_config(&self, cfg: Arc<RateLimitConfig>) {
        self.rate_limit_cfg.store(cfg);
    }

    /// Load `configs/tx-velocity.yaml` once and start the hot-reload watcher.
    ///
    /// Bad YAML or a missing file logs a warning and leaves the subsystem
    /// inert (default disabled config) — the gateway never refuses to start
    /// because of a tx-velocity config issue.
    pub fn start_tx_velocity_watcher(&self, path: &Path) {
        if self.tx_velocity_reloader.get().is_some() {
            return;
        }
        match TxVelocityFileConfig::from_path(path) {
            Ok(cfg) => {
                self.tx_velocity_cfg.store(cfg);
                info!(file = %path.display(), "tx_velocity: initial config loaded");
            }
            Err(e) => {
                warn!(file = %path.display(), error = %e, "tx_velocity: initial load failed; using disabled config");
            }
        }
        match TxVelocityReloader::start(path.to_path_buf(), Arc::clone(&self.tx_velocity_cfg), None) {
            Ok(r) => {
                let _ = self.tx_velocity_reloader.set(r);
            }
            Err(e) => warn!(
                file = %path.display(),
                error = %e,
                "tx_velocity: hot-reload watcher failed to start; running without hot-reload"
            ),
        }
    }

    /// Load `configs/ddos.yaml` once and start the hot-reload watcher.
    ///
    /// Bad YAML or a missing file logs a warning and leaves the subsystem
    /// inert (default empty config) — the gateway never refuses to start
    /// because of a `DDoS` config issue.
    pub fn start_ddos_watcher(&self, path: &Path) {
        if self.ddos_reloader.get().is_some() {
            return;
        }
        match DdosFileConfig::from_path(path) {
            Ok(cfg) => {
                self.ddos_cfg.store(cfg);
                info!(file = %path.display(), "ddos: initial config loaded");
            }
            Err(e) => {
                warn!(file = %path.display(), error = %e, "ddos: initial load failed; using empty config");
            }
        }
        match DdosReloader::start(path.to_path_buf(), Arc::clone(&self.ddos_cfg), DDOS_DEBOUNCE_MS) {
            Ok(r) => {
                let _ = self.ddos_reloader.set(r);
            }
            Err(e) => warn!(
                file = %path.display(),
                error = %e,
                "ddos: hot-reload watcher failed to start; running without hot-reload"
            ),
        }
    }

    /// Load geo rules from the admin API's `configs/geo-rules.yaml` into
    /// `geo_check`, replacing the full rule set (hosts absent from the file
    /// are cleared). Fail-soft: a missing/bad file logs a warning and leaves
    /// the existing rules in place.
    pub fn load_geo_rules(&self, path: &Path) {
        if let Err(e) = crate::checks::apply_geo_rules(&self.geo_check, path) {
            warn!(file = %path.display(), error = %e, "geo rules: load failed; keeping existing rules");
        }
    }

    /// Load `configs/geo-rules.yaml` once and start the hot-reload watcher.
    ///
    /// The admin API writes the same file, so geo rule CRUD hot-reloads with
    /// no extra API→engine call. Missing/bad file leaves `geo_check` empty —
    /// the gateway never refuses to start because of a geo config issue.
    pub fn start_geo_watcher(&self, path: &Path) {
        if self.geo_reloader.get().is_some() {
            return;
        }
        self.load_geo_rules(path);
        match crate::checks::GeoReloader::start(path.to_path_buf(), Arc::clone(&self.geo_check), GEO_DEBOUNCE_MS) {
            Ok(r) => {
                let _ = self.geo_reloader.set(r);
            }
            Err(e) => warn!(
                file = %path.display(),
                error = %e,
                "geo rules: hot-reload watcher failed to start; running without hot-reload"
            ),
        }
    }

    /// Threat-intel feed metadata snapshot (D3). Empty until
    /// [`Self::load_relay_feeds`] runs at startup.
    #[must_use]
    pub fn relay_feeds(&self) -> Arc<Vec<crate::relay::FeedMeta>> {
        self.relay_feeds.load_full()
    }

    /// Load `configs/relay.yaml` and populate the threat-intel feed metadata.
    ///
    /// Fail-soft: a missing/invalid file leaves the feed list empty and logs a
    /// warning — the gateway never refuses to start over an intel-config issue.
    pub fn load_relay_feeds(&self, path: &Path) {
        match crate::relay::RelayConfig::from_yaml_path(path) {
            Ok(cfg) => {
                let feeds = crate::relay::load_feed_metadata(&cfg);
                self.relay_feeds.store(Arc::new(feeds));
                tracing::info!(file = %path.display(), "relay-intel: feed metadata loaded");
            }
            Err(e) => {
                tracing::warn!(file = %path.display(), error = %e, "relay-intel: feed metadata load failed; empty list");
            }
        }
    }

    /// Get reference to `DDoS` metrics for external access.
    #[must_use]
    pub fn ddos_metrics(&self) -> &Arc<DdosMetrics> {
        self.ddos_check.metrics()
    }

    /// Get reference to `DDoS` ban table for external access (e.g., purge task).
    #[must_use]
    pub fn ddos_ban_table(&self) -> &Arc<DynamicBanTable> {
        self.ddos_check.ban_table()
    }

    /// Set the root rules directory used by the file-based custom rule
    /// loader (FR-003). Call before `reload_rules` to take effect.
    pub fn set_rules_dir(&self, dir: PathBuf) {
        let _ = self.rules_dir.set(dir);
    }

    /// Reload only file-based custom rules without touching the database.
    ///
    /// Used by worker nodes (`StorageMode::ForwardOnly`) that have no DB
    /// connection. Clears any previously loaded file rules and re-scans
    /// the rules directory. DB-sourced rules are left untouched.
    pub fn reload_file_rules(&self) {
        let rules_dir = self.rules_dir.get().cloned().unwrap_or_else(|| PathBuf::from("rules"));
        self.custom_rules.clear_file_rules();
        match crate::rules::custom_file_loader::load_dir(&rules_dir) {
            Ok(file_rules) => {
                let count = file_rules.len();
                for rule in file_rules {
                    self.custom_rules.add_file_rule(rule);
                }
                if count > 0 {
                    info!("Reloaded {count} file-based rules from {rules_dir:?}");
                }
            }
            Err(e) => warn!("File rule reload failed: {e}"),
        }
    }

    /// Start the FR-003 hot-reload watcher on `<rules_dir>/custom/`.
    ///
    /// Must be called after `set_rules_dir` + initial `reload_rules`. Creation
    /// failure (e.g. permission denied on the directory) is logged and the
    /// service continues without hot-reload — rules already loaded keep
    /// working, the operator just has to restart to pick up edits.
    pub fn start_file_watcher(&self) {
        if self.file_watcher.get().is_some() {
            return;
        }
        let rules_dir = self.rules_dir.get().cloned().unwrap_or_else(|| PathBuf::from("rules"));
        match CustomRuleFileWatcher::spawn(rules_dir, Arc::clone(&self.custom_rules)) {
            Ok(w) => {
                let _ = self.file_watcher.set(w);
            }
            Err(e) => warn!(error = %e, "Custom-rule file watcher failed to start; continuing without hot-reload"),
        }
    }

    /// Plug `CrowdSec` components into the engine (called once after init).
    pub fn set_crowdsec(&self, checker: Arc<CrowdSecChecker>, appsec: Option<Arc<AppSecClient>>) {
        let _ = self.crowdsec_checker.set(checker);
        if let Some(ac) = appsec {
            let _ = self.appsec_client.set(ac);
        }
    }

    /// Plug the community checker into the engine (called once after init).
    pub fn set_community(&self, checker: Arc<CommunityChecker>) {
        let _ = self.community_checker.set(checker);
    }

    /// Plug the community signal reporter into the engine (called once after init).
    ///
    /// When set, every WAF detection (block or `log_only`) is pushed to the
    /// community reporter buffer for eventual batch upload.
    pub fn set_community_reporter(&self, reporter: Arc<CommunityReporter>) {
        let _ = self.community_reporter.set(reporter);
    }

    /// Plug the `GeoIP` lookup service into the engine (called once after init).
    ///
    /// After this call every request will have its `ctx.geo` populated before
    /// the checker pipeline runs, enabling `GeoIP`-based rules.
    pub fn set_geoip(&self, service: Arc<GeoIpService>) {
        let _ = self.geoip.set(service);
    }

    /// Look up `GeoIP` info for `ip`. Returns `None` when the service is
    /// disabled/unset; returns a (possibly empty) `GeoIpInfo` otherwise.
    #[must_use]
    pub fn geoip_lookup(&self, ip: std::net::IpAddr) -> Option<waf_common::GeoIpInfo> {
        self.geoip.get().map(|svc| svc.lookup(ip))
    }

    /// Plug the audit file sink sender into the engine (called once during
    /// server init when `[audit] enabled = true`).
    pub fn set_audit_sender(&self, sender: Arc<AuditSender>) {
        let _ = self.audit_sender.set(sender);
    }

    /// Emit a minimal audit-log entry for egress paths that have NO
    /// `RequestCtx` (fail-closed 503, transport error before inspect).
    /// Used to correlate a fallback-UUID `X-WAF-Request-Id` with at least
    /// one audit record so the wire header is never an orphan.
    ///
    /// Fire-and-forget — no-op when the audit sender is unset.
    pub fn emit_minimal_audit_stub(&self, stub: &MinimalAuditStub) {
        let Some(sender) = self.audit_sender.get() else {
            return;
        };
        let event = AuditEvent {
            timestamp: chrono::Utc::now(),
            event_type: stub.event_type,
            rule_name: String::new(),
            rule_id: None,
            phase: None,
            peer_ip: stub.peer_ip.to_string(),
            client_ip: stub.peer_ip.to_string(),
            host: stub.host.to_string(),
            method: stub.method.to_string(),
            path: stub.path.to_string(),
            tier: None,
            detail: Some(stub.detail.to_string()),
            req_id: Some(stub.req_id.to_string()),
            risk_score: 0,
            mode: InteropMode::Enforce,
            query: String::new(),
            contract_action: stub.action,
        };
        sender.send(event);
    }

    /// Plug the batched DB log writer into the engine (called once after init).
    ///
    /// After this call, `log_attack` and `log_security_event` use bounded
    /// `try_send` instead of per-event `tokio::spawn`.
    pub fn set_db_batch_writer(&self, writer: DbBatchWriter) {
        let _ = self.db_batch_writer.set(writer);
    }

    pub fn set_mode_registry(&self, mr: ModeRegistry) {
        let _ = self.mode_registry.set(mr);
    }

    fn apply_mode(&self, ctx: &RequestCtx, decision: &mut WafDecision, feature: &str, policy: Option<&str>) {
        let registry_log_only = self
            .mode_registry
            .get()
            .is_some_and(|mr| mr.resolve(feature, policy) == InteropMode::LogOnly);
        if registry_log_only || ctx.host_config.log_only_mode {
            decision.mode = InteropMode::LogOnly;
        }
    }

    /// Return a reference to the `GeoCheck` so callers can load rules.
    pub const fn geo_check(&self) -> &Arc<GeoCheck> {
        &self.geo_check
    }

    /// Clear all temporary runtime state across engine subsystems.
    pub fn reset_runtime_state(&self) {
        for checker in &self.checkers {
            checker.reset_state();
        }
        self.ddos_ban_table().clear();
        // Keep the active-ban gauge in sync with the now-empty table; clearing
        // the table alone would leave `bans_active` drifting upward.
        self.ddos_metrics().reset_bans_active();
        self.tx_velocity_store.clear_all();
    }

    /// Hot-reload `SQLi` scan configuration without restarting.
    pub fn reload_sqli_scan_config(&self, cfg: SqliScanConfig) {
        self.sqli_check.reload_config(cfg);
    }

    /// Reload all rules from the database
    pub async fn reload_rules(&self) -> anyhow::Result<()> {
        // Reload IP/URL rules
        self.store.reload_all().await?;

        // Reload custom rules
        let custom_rules = self.db.list_custom_rules(None).await?;
        {
            let mut by_host: std::collections::HashMap<String, Vec<_>> = std::collections::HashMap::new();
            for row in &custom_rules {
                match from_db_rule(row) {
                    Ok(rule) => {
                        by_host.entry(row.host_code.clone()).or_default().push(rule);
                    }
                    Err(e) => warn!("Failed to parse custom rule {}: {}", row.id, e),
                }
            }
            for (host_code, rules) in by_host {
                self.custom_rules.load_host(&host_code, rules);
            }
        }

        // ── FR-003: file-based custom rules ──────────────────────────────────
        // DB load above used `load_host` which replaces buckets — so any prior
        // file rules are already cleared. Append fresh file rules with `add_rule`;
        // they sort into the same priority-ordered bucket as DB rules.
        let rules_dir = self.rules_dir.get().cloned().unwrap_or_else(|| PathBuf::from("rules"));
        match crate::rules::custom_file_loader::load_dir(&rules_dir) {
            Ok(file_rules) => {
                let count = file_rules.len();
                for rule in file_rules {
                    self.custom_rules.add_file_rule(rule);
                }
                if count > 0 {
                    info!("Loaded {count} file-based custom rules from {rules_dir:?}");
                }
            }
            Err(e) => warn!("Custom rule file load failed: {e}"),
        }

        // Reload sensitive patterns
        let patterns = self.db.list_sensitive_patterns(None).await?;
        {
            let mut by_host: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
            for row in &patterns {
                if row.check_request {
                    by_host
                        .entry(row.host_code.clone())
                        .or_default()
                        .push(row.pattern.clone());
                }
            }
            for (host_code, pats) in by_host {
                self.sensitive.load_host(&host_code, &pats);
            }
        }

        // Reload hotlink configs
        let hotlink_configs = self.db.list_hotlink_configs().await?;
        for row in &hotlink_configs {
            let domains: Vec<String> = row
                .allowed_domains
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                .unwrap_or_default();
            let config = crate::checks::anti_hotlink::HotlinkConfig {
                enabled: row.enabled,
                allow_empty_referer: row.allow_empty_referer,
                allowed_domains: domains,
                redirect_url: row.redirect_url.clone(),
            };
            self.hotlink.set_config(&row.host_code, config);
        }

        Ok(())
    }

    /// Run the full WAF inspection pipeline.
    ///
    /// `ctx` is taken as `&mut` so the engine can enrich it with `GeoIP` data
    /// before the checker pipeline runs.  Callers should check
    /// `decision.is_enforcement_allowed()`.
    pub async fn inspect(&self, ctx: &mut RequestCtx) -> WafDecision {
        let inspect_time = chrono::Utc::now();
        let now_ms = inspect_time.timestamp_millis();

        let (mut decision, fast_path) = self.inspect_pipeline(ctx).await;
        // Fast-path exits (guard off, IP/URL allow/block lists) skip risk
        // scoring entirely: no store write, risk_score stays 0.
        if matches!(fast_path, FastPath::Miss)
            && let Ok(scorer_result) = self.scorer.load_full().score(ctx, None, &[], None, now_ms).await
        {
            let risk_score = scorer_result.score.min(100);
            decision.risk_score = risk_score;
            // FR-025 enforcement: escalation-only gate. A scorer Block or
            // Challenge replaces the pipeline decision only when that decision
            // is a plain Allow. Any decision carrying a detection — enforced
            // or downgraded to LogOnly by a monitored feature — is returned
            // untouched; a scorer Allow never downgrades anything.
            if matches!(decision.action, WafAction::Allow)
                && matches!(scorer_result.action, WafAction::Block { .. } | WafAction::Challenge)
            {
                let mut risk_decision = Self::make_risk_decision(ctx, &scorer_result);
                self.apply_mode(ctx, &mut risk_decision, "risk_assessment", Some("cumulative_risk"));
                self.log_security_event(ctx, &risk_decision);
                self.report_community_signal(ctx, &risk_decision);
                risk_decision.risk_score = risk_score;
                decision = risk_decision;
            }
        }
        self.send_audit_event(ctx, &decision, inspect_time);
        decision
    }

    /// Build the Block/Challenge decision for a risk-scorer escalation.
    ///
    /// All risk enforcement events carry `Phase::RiskScore` and the single
    /// rule name `cumulative_risk` (threshold, pinned-actor, and canary hits
    /// alike — canary hits stay distinguishable via the scorer's info log).
    /// Mode resolution is handled by `apply_mode()` at the call site.
    fn make_risk_decision(ctx: &RequestCtx, scorer_result: &ScorerResult) -> WafDecision {
        let result = DetectionResult {
            rule_id: None,
            rule_name: "cumulative_risk".to_string(),
            phase: waf_common::Phase::RiskScore,
            detail: format!("risk score {}", scorer_result.score),
            rule_action: None,
            action_status: None,
        };
        match scorer_result.action {
            WafAction::Block { status, .. } => {
                let body = render_block_page(ctx, "cumulative_risk");
                WafDecision::block(status, Some(body), result)
            }
            _ => WafDecision {
                action: WafAction::Challenge,
                result: Some(result),
                risk_score: 0,
                mode: InteropMode::Enforce,
                rule_id: None,
            },
        }
    }

    /// Original inspection pipeline. Split out of [`Self::inspect`] so the
    /// outer wrapper can attach the risk score to every decision without
    /// rewriting each early-return branch. The `FastPath` tag tells the
    /// wrapper whether the decision came from a pre-scoring fast-path exit.
    async fn inspect_pipeline(&self, ctx: &mut RequestCtx) -> (WafDecision, FastPath) {
        // Skip WAF if guard is disabled for this host
        if !ctx.host_config.guard_status {
            return (WafDecision::allow(), FastPath::Hit);
        }

        // ── GeoIP enrichment — populate ctx.geo before any checks ────────────
        if let Some(geoip) = self.geoip.get() {
            ctx.geo = Some(geoip.lookup(ctx.client_ip));
        }

        // ── Phase 1: IP Whitelist — allow immediately if matched ──────────────
        let ip_whitelist = check_ip_whitelist(ctx, &self.store);
        if let Some(ref result) = ip_whitelist.result
            && matches!(ip_whitelist.action, WafAction::Allow)
            && result.phase == waf_common::Phase::IpWhitelist
        {
            debug!("Request allowed by IP whitelist: {}", ctx.client_ip);
            return (ip_whitelist, FastPath::Hit);
        }

        // ── Phase 2: IP Blacklist — block if matched ───────────────────────────
        let mut ip_blacklist = check_ip_blacklist(ctx, &self.store);
        self.apply_mode(ctx, &mut ip_blacklist, "access_control", Some("ip_blacklist"));
        if !ip_blacklist.is_enforcement_allowed() {
            self.log_attack(ctx, &ip_blacklist);
            self.report_community_signal(ctx, &ip_blacklist);
            return (ip_blacklist, FastPath::Hit);
        }

        // ── Phase 3: URL Whitelist — allow immediately if matched ──────────────
        if let Some(url_wl) = check_url_whitelist(ctx, &self.store) {
            debug!("Request allowed by URL whitelist: {}", ctx.path);
            return (url_wl, FastPath::Hit);
        }

        // ── Phase 4: URL Blacklist — block if matched ──────────────────────────
        let mut url_bl = check_url_blacklist(ctx, &self.store);
        self.apply_mode(ctx, &mut url_bl, "access_control", Some("url_blacklist"));
        if !url_bl.is_enforcement_allowed() {
            self.log_attack(ctx, &url_bl);
            self.report_community_signal(ctx, &url_bl);
            return (url_bl, FastPath::Hit);
        }

        // ── Phase 19: DDoS burst detection (FR-005) ───────────────────────────
        // Runs AFTER allowlist/blacklist (fast-path) and BEFORE rate-limit.
        // Banned IPs are blocked here; burst detection may trigger new bans.
        if let Some(result) = self.ddos_check.check(ctx) {
            let phase = result.phase;
            let rule_name = result.rule_name.clone();
            let mut decision = Self::make_block_decision(ctx, &rule_name, result, 403);
            let (feat, pol) = phase_feature_identity(phase);
            self.apply_mode(ctx, &mut decision, feat, pol);
            self.log_security_event(ctx, &decision);
            self.report_community_signal(ctx, &decision);
            return (decision, FastPath::Miss);
        }

        // ── Phase 16a: CrowdSec Bouncer — fast cache lookup ───────────────────
        if let Some(cs) = self.crowdsec_checker.get()
            && let Some(result) = cs.check(ctx)
        {
            let phase = result.phase;
            let rule_name = result.rule_name.clone();
            let mut decision = Self::make_block_decision(ctx, &rule_name, result, 403);
            let (feat, pol) = phase_feature_identity(phase);
            self.apply_mode(ctx, &mut decision, feat, pol);
            self.log_security_event(ctx, &decision);
            self.report_community_signal(ctx, &decision);
            return (decision, FastPath::Miss);
        }

        // ── Phase 18: Community blocklist ─────────────────────────────────────
        if let Some(cc) = self.community_checker.get()
            && let Some(result) = cc.check(ctx)
        {
            let phase = result.phase;
            let rule_name = result.rule_name.clone();
            let mut decision = Self::make_block_decision(ctx, &rule_name, result, 403);
            let (feat, pol) = phase_feature_identity(phase);
            self.apply_mode(ctx, &mut decision, feat, pol);
            self.log_security_event(ctx, &decision);
            return (decision, FastPath::Miss);
        }

        // ── Phase 17: GeoIP access control ────────────────────────────────────
        if let Some(result) = self.geo_check.check(ctx) {
            let phase = result.phase;
            let rule_name = result.rule_name.clone();
            let mut decision = Self::make_block_decision(ctx, &rule_name, result, 403);
            let (feat, pol) = phase_feature_identity(phase);
            self.apply_mode(ctx, &mut decision, feat, pol);
            self.log_security_event(ctx, &decision);
            self.report_community_signal(ctx, &decision);
            return (decision, FastPath::Miss);
        }

        // ── Phase 5-11: Attack detection pipeline ─────────────────────────────
        for checker in &self.checkers {
            if let Some(result) = checker.check(ctx) {
                let phase = result.phase;
                let rule_name = result.rule_name.clone();

                let decision = if phase == waf_common::Phase::RateLimit {
                    let body = render_block_page(ctx, &rule_name);
                    let mut d = WafDecision::rate_limit(429, Some(body), result);
                    self.apply_mode(ctx, &mut d, "rate_limiting", Some("per_ip"));
                    d
                } else {
                    let mut d = Self::make_block_decision(ctx, &rule_name, result, 403);
                    let (feat, pol) = phase_feature_identity(phase);
                    self.apply_mode(ctx, &mut d, feat, pol);
                    d
                };

                self.log_security_event(ctx, &decision);
                self.report_community_signal(ctx, &decision);
                return (decision, FastPath::Miss);
            }
        }

        // ── SQLi check (separate for hot-reload support) ─────────────────────
        if let Some(result) = self.sqli_check.check(ctx) {
            let phase = result.phase;
            let rule_name = result.rule_name.clone();
            let mut decision = Self::make_block_decision(ctx, &rule_name, result, 403);
            let (feat, pol) = phase_feature_identity(phase);
            self.apply_mode(ctx, &mut decision, feat, pol);
            self.log_security_event(ctx, &decision);
            self.report_community_signal(ctx, &decision);
            return (decision, FastPath::Miss);
        }

        // ── Phase 16b: CrowdSec AppSec — async per-request check ──────────────
        if let Some(appsec) = self.appsec_client.get() {
            match appsec.check_request(ctx).await {
                AppSecResult::Block { message } => {
                    let result = appsec_to_detection(message);
                    let phase = result.phase;
                    let rule_name = result.rule_name.clone();
                    let mut decision = Self::make_block_decision(ctx, &rule_name, result, 403);
                    let (feat, pol) = phase_feature_identity(phase);
                    self.apply_mode(ctx, &mut decision, feat, pol);
                    self.log_security_event(ctx, &decision);
                    self.report_community_signal(ctx, &decision);
                    return (decision, FastPath::Miss);
                }
                AppSecResult::Allow | AppSecResult::Unavailable => {}
            }
        }

        // ── Phase 12: Custom rules engine ─────────────────────────────────────
        if let Some(result) = self.custom_rules.check(ctx) {
            let rule_name = result.rule_name.clone();
            // Custom rules carry their own action intent/status overrides, so this
            // branch builds the action directly instead of using make_block_decision.
            let action_intent = result.rule_action.unwrap_or(RuleAction::Block);
            let status = result.action_status.unwrap_or(403);
            let body = if action_intent == RuleAction::Block {
                Some(render_block_page(ctx, &rule_name))
            } else {
                None
            };
            let rule_id = result.rule_id.clone();
            let mut decision = WafDecision {
                action: action_intent.to_waf_action(status, body),
                result: Some(result),
                risk_score: 0,
                mode: InteropMode::Enforce,
                rule_id,
            };
            self.apply_mode(ctx, &mut decision, "custom_rules", None);
            self.log_security_event(ctx, &decision);
            self.report_community_signal(ctx, &decision);
            // Allow/Log: log the match but continue pipeline (phases 13-16 still run)
            // Block/Challenge: return immediately. In log-only mode enforcement is
            // bypassed (mode = LogOnly), so even a Block intent continues the pipeline.
            if !decision.is_enforcement_allowed() {
                return (decision, FastPath::Miss);
            }
        }

        // ── Phase 13: OWASP CRS ────────────────────────────────────────────────
        if let Some(result) = self.owasp.check(ctx) {
            let phase = result.phase;
            let rule_name = result.rule_name.clone();
            let mut decision = Self::make_block_decision(ctx, &rule_name, result, 403);
            let (feat, pol) = phase_feature_identity(phase);
            self.apply_mode(ctx, &mut decision, feat, pol);
            self.log_security_event(ctx, &decision);
            self.report_community_signal(ctx, &decision);
            return (decision, FastPath::Miss);
        }

        // ── Phase 14: Sensitive data ───────────────────────────────────────────
        if let Some(result) = self.sensitive.check(ctx) {
            let phase = result.phase;
            let rule_name = result.rule_name.clone();
            let mut decision = Self::make_block_decision(ctx, &rule_name, result, 403);
            let (feat, pol) = phase_feature_identity(phase);
            self.apply_mode(ctx, &mut decision, feat, pol);
            self.log_security_event(ctx, &decision);
            self.report_community_signal(ctx, &decision);
            return (decision, FastPath::Miss);
        }

        // ── Phase 15: Anti-hotlinking ──────────────────────────────────────────
        if let Some(result) = self.hotlink.check(ctx) {
            let phase = result.phase;
            let rule_name = result.rule_name.clone();
            let mut decision = Self::make_block_decision(ctx, &rule_name, result, 403);
            let (feat, pol) = phase_feature_identity(phase);
            self.apply_mode(ctx, &mut decision, feat, pol);
            self.log_security_event(ctx, &decision);
            self.report_community_signal(ctx, &decision);
            return (decision, FastPath::Miss);
        }

        (WafDecision::allow(), FastPath::Miss)
    }

    /// Build a Block decision. Mode resolution (`LogOnly` / `Enforce`) is
    /// handled by `apply_mode()` at each call site — this function is a pure
    /// decision factory.
    fn make_block_decision(ctx: &RequestCtx, rule_name: &str, result: DetectionResult, status: u16) -> WafDecision {
        let body = render_block_page(ctx, rule_name);
        WafDecision::block(status, Some(body), result)
    }

    /// Dispatch an upstream response status to every registered `Check`.
    ///
    /// Gateway callers invoke this from Pingora's `response_filter` after
    /// extracting the status code. Most checks inherit the no-op default and
    /// ignore the call; FR-018 brute-force records 401/403 as login
    /// failures and FR-019 scanner (future) will count 4xx/5xx bursts.
    ///
    /// Sync on purpose — there's no body or await in v1. The work inside
    /// each `on_response` impl is a bounded state insert (`DashMap` +
    /// `Mutex` push).
    pub fn on_response(&self, ctx: &RequestCtx, status: u16) {
        for check in &self.checkers {
            check.on_response(ctx, status);
        }
        self.sqli_check.on_response(ctx, status);
    }

    /// Dispatch a request-complete event to every registered `Check`.
    ///
    /// Gateway callers invoke this from Pingora's `logging()` hook — fires
    /// once per request at completion (post-body). `upstream_reached` is
    /// `false` for WAF-blocked or origin-down requests. FR-012 `tx_velocity`
    /// uses this to set the honest `Outcome` on recorded events.
    pub fn on_request_complete(&self, ctx: &RequestCtx, status: u16, upstream_reached: bool) {
        for check in &self.checkers {
            check.on_request_complete(ctx, status, upstream_reached);
        }
    }

    // ── Logging helpers ───────────────────────────────────────────────────────

    /// Log a Phase 1/2 event to the `attack_logs` table (fire-and-forget).
    fn log_attack(&self, ctx: &RequestCtx, decision: &WafDecision) {
        let Some(result) = &decision.result else {
            return;
        };

        #[allow(deprecated)]
        let action_str = match &decision.action {
            WafAction::Block { .. } => "block",
            WafAction::Allow => "allow",
            WafAction::LogOnly => "log_only",
            WafAction::Redirect { .. } => "redirect",
            WafAction::Challenge => "challenge",
            WafAction::RateLimit { .. } => "rate_limit",
            WafAction::Timeout { .. } => "timeout",
            WafAction::CircuitBreaker { .. } => "circuit_breaker",
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
            geo_info: ctx.geo.as_ref().map(|g| {
                serde_json::json!({
                    "country": g.country,
                    "province": g.province,
                    "city": g.city,
                    "isp": g.isp,
                    "iso_code": g.iso_code,
                })
            }),
            created_at: chrono::Utc::now(),
        };

        if let Some(writer) = self.db_batch_writer.get() {
            writer.try_send(DbLogEvent::Attack(log));
        } else {
            let db = Arc::clone(&self.db);
            tokio::spawn(async move {
                if let Err(e) = db.create_attack_log(log).await {
                    warn!("Failed to log attack event: {}", e);
                }
            });
        }
    }

    /// Log a Phase 2+ security event to the `security_events` table (fire-and-forget).
    fn log_security_event(&self, ctx: &RequestCtx, decision: &WafDecision) {
        let Some(result) = &decision.result else {
            return;
        };

        #[allow(deprecated)]
        let action_str = match &decision.action {
            WafAction::Block { .. } => "block",
            WafAction::Allow => "allow",
            WafAction::LogOnly => "log_only",
            WafAction::Redirect { .. } => "redirect",
            WafAction::Challenge => "challenge",
            WafAction::RateLimit { .. } => "rate_limit",
            WafAction::Timeout { .. } => "timeout",
            WafAction::CircuitBreaker { .. } => "circuit_breaker",
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
            geo_info: ctx.geo.as_ref().map(|g| {
                serde_json::json!({
                    "country": g.country,
                    "province": g.province,
                    "city": g.city,
                    "isp": g.isp,
                    "iso_code": g.iso_code,
                })
            }),
            waf_mode: decision.mode.as_contract_str().to_string(),
            tier: Some(format!("{:?}", ctx.tier)),
        };

        if let Some(writer) = self.db_batch_writer.get() {
            writer.try_send(DbLogEvent::Security(event));
        } else {
            let db = Arc::clone(&self.db);
            tokio::spawn(async move {
                if let Err(e) = db.create_security_event(event).await {
                    warn!("Failed to log security event: {}", e);
                }
            });
        }
    }

    /// Write a non-Allow decision to the audit file sink.
    ///
    /// Fire-and-forget: drops silently when the audit sender is unset
    /// (no `[audit]` config) or its buffer is saturated.
    /// The hot path never blocks on observability.
    fn send_audit_event(&self, ctx: &RequestCtx, decision: &WafDecision, timestamp: chrono::DateTime<chrono::Utc>) {
        let Some(sender) = self.audit_sender.get() else {
            return;
        };

        #[allow(deprecated)]
        let event_type = match &decision.action {
            WafAction::Block { .. }
            | WafAction::RateLimit { .. }
            | WafAction::Timeout { .. }
            | WafAction::CircuitBreaker { .. } => AuditEventType::Block,
            WafAction::Allow => AuditEventType::Allow,
            WafAction::LogOnly => AuditEventType::LogOnly,
            WafAction::Redirect { .. } | WafAction::Challenge => AuditEventType::Challenge,
        };

        #[allow(clippy::option_if_let_else)]
        let (rule_name, rule_id, phase, detail) = match &decision.result {
            Some(r) => (
                r.rule_name.clone(),
                r.rule_id.clone(),
                Some(r.phase.to_string()),
                Some(r.detail.clone()),
            ),
            None => (String::new(), None, None, None),
        };

        let event = AuditEvent {
            timestamp,
            event_type,
            rule_name,
            rule_id,
            phase,
            peer_ip: ctx.peer_ip.to_string(),
            client_ip: ctx.client_ip.to_string(),
            host: ctx.host.clone(),
            method: ctx.method.clone(),
            path: ctx.path.clone(),
            tier: Some(format!("{:?}", ctx.tier)),
            detail,
            req_id: Some(ctx.req_id.clone()),
            risk_score: decision.risk_score,
            mode: decision.mode,
            query: ctx.query.clone(),
            contract_action: decision.action.as_contract_str(),
        };
        sender.send(event);
    }

    /// Push a detection signal to the community reporter via bounded channel.
    ///
    /// This is a **synchronous** call on the hot path — no `tokio::spawn`,
    /// no async mutex, just a single `try_send` into an MPSC channel.
    /// When the channel is full (back-pressure from flood traffic), the signal is silently
    /// dropped and the reporter logs the drop count periodically.
    fn report_community_signal(&self, ctx: &RequestCtx, decision: &WafDecision) {
        let Some(reporter) = self.community_reporter.get() else {
            return;
        };
        let Some(result) = &decision.result else {
            return;
        };

        let req_info = RequestInfo {
            http_method: ctx.method.clone(),
            request_path: ctx.path.clone(),
            request_host: ctx.host.clone(),
            geo_country: ctx.geo.as_ref().map(|g| g.iso_code.clone()),
        };

        reporter.try_push_detection(ctx.client_ip, result, Some(&req_info));
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::IpAddr;

    use bytes::Bytes;
    use testcontainers::runners::AsyncRunner;
    use testcontainers_modules::postgres::Postgres as PostgresImage;
    use testcontainers_modules::testcontainers::ImageExt;
    use waf_common::HostConfig;
    use waf_storage::models::{CreateHost, CreateIpRule};

    use super::*;

    fn make_ctx(host_code: &str, path: &str, ip: &str) -> RequestCtx {
        let host_config = Arc::new(HostConfig {
            code: host_code.into(),
            host: "risk.example.com".into(),
            ..HostConfig::default()
        });
        RequestCtx {
            req_id: "fx".into(),
            client_ip: ip.parse::<IpAddr>().expect("ip parse"),
            peer_ip: ip.parse::<IpAddr>().expect("ip parse"),
            client_port: 12345,
            method: "GET".into(),
            host: "risk.example.com".into(),
            port: 80,
            path: path.into(),
            query: String::new(),
            headers: HashMap::from([(
                "user-agent".into(),
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0".into(),
            )]),
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config,
            geo: None,
            tier: waf_common::tier::Tier::CatchAll,
            tier_policy: RequestCtx::default_tier_policy(),
            cookies: HashMap::new(),
            device_fp: None,
            tx_velocity_token: None,
        }
    }

    /// Fast-path exits (here: IP whitelist) must skip risk scoring entirely —
    /// zero risk-store writes — while a normal allowed request still scores
    /// and writes state.
    ///
    /// Uses a Postgres testcontainer by default; set `PG_TEST_URL` to point at
    /// an existing scratch database instead (environments without Docker
    /// socket access).
    #[tokio::test(flavor = "multi_thread")]
    async fn fast_path_exits_skip_risk_scoring() {
        let (url, _container) = if let Ok(url) = std::env::var("PG_TEST_URL") {
            (url, None)
        } else {
            let container = PostgresImage::default()
                .with_tag("16-alpine")
                .start()
                .await
                .expect("start postgres testcontainer");
            let host = container.get_host().await.expect("container host");
            let port = container.get_host_port_ipv4(5432).await.expect("container port");
            (
                format!("postgres://postgres:postgres@{host}:{port}/postgres"),
                Some(container),
            )
        };
        let db = Database::connect(&url, 5).await.expect("db connect");
        db.migrate().await.expect("migrate");
        let db = Arc::new(db);
        let engine = WafEngine::new(Arc::clone(&db), WafEngineConfig::default());

        engine.replace_risk_config(RiskConfig {
            enabled: true,
            ..RiskConfig::default()
        });

        let host_row = db
            .create_host(CreateHost {
                host: "risk.example.com".into(),
                port: 80,
                ssl: false,
                guard_status: true,
                remote_host: "127.0.0.1".into(),
                remote_port: 8080,
                remote_ip: None,
                cert_file: None,
                key_file: None,
                remarks: None,
                start_status: true,
                log_only_mode: false,
                upstream_alpn: "h2h1".to_string(),
                upstream_skip_ssl_verify: false,
                defense_json: None,
                http_redirect: false,
                preserve_host: true,
            })
            .await
            .expect("create host");
        db.create_allow_ip(CreateIpRule {
            host_code: host_row.code.clone(),
            ip_cidr: "203.0.113.7/32".into(),
            remarks: None,
        })
        .await
        .expect("seed allow ip");
        engine.reload_rules().await.expect("reload");

        // Whitelisted IP: fast-path exit → no scoring, no store write.
        let mut ctx = make_ctx(&host_row.code, "/", "203.0.113.7");
        let decision = engine.inspect(&mut ctx).await;
        assert!(matches!(decision.action, WafAction::Allow), "whitelisted IP must allow");
        assert_eq!(decision.risk_score, 0, "fast-path decision must carry risk_score 0");
        assert!(
            engine.scorer.load().store().is_empty().await,
            "fast-path request must not write the risk store"
        );

        // Normal request: scored → store written.
        let mut ctx = make_ctx(&host_row.code, "/", "198.51.100.9");
        let decision = engine.inspect(&mut ctx).await;
        assert!(matches!(decision.action, WafAction::Allow), "clean request must allow");
        assert!(
            !engine.scorer.load().store().is_empty().await,
            "scored request must write the risk store"
        );
    }

    /// Spin up an engine on a scratch Postgres. Enforcement tests need no DB
    /// rules, so no host row is created — `make_ctx` carries the host config.
    async fn spawn_engine() -> (WafEngine, Option<testcontainers::ContainerAsync<PostgresImage>>) {
        let (url, container) = if let Ok(url) = std::env::var("PG_TEST_URL") {
            (url, None)
        } else {
            let container = PostgresImage::default()
                .with_tag("16-alpine")
                .start()
                .await
                .expect("start postgres testcontainer");
            let host = container.get_host().await.expect("container host");
            let port = container.get_host_port_ipv4(5432).await.expect("container port");
            (
                format!("postgres://postgres:postgres@{host}:{port}/postgres"),
                Some(container),
            )
        };
        let db = Database::connect(&url, 5).await.expect("db connect");
        db.migrate().await.expect("migrate");
        let engine = WafEngine::new(Arc::new(db), WafEngineConfig::default());
        (engine, container)
    }

    /// `make_ctx` with custom risk thresholds. `challenge` mirrors `allow` —
    /// only the allow/block boundaries drive `threshold::decide`.
    fn make_ctx_with_thresholds(path: &str, ip: &str, allow: u32, block: u32) -> RequestCtx {
        use waf_common::tier::{CachePolicy, FailMode, RiskThresholds, TierPolicy};

        let mut ctx = make_ctx("risk-test", path, ip);
        ctx.tier_policy = Arc::new(TierPolicy {
            fail_mode: FailMode::Open,
            ddos_threshold_rps: 1000,
            cache_policy: CachePolicy::NoCache,
            risk_thresholds: RiskThresholds {
                allow,
                challenge: allow,
                block,
            },
        });
        ctx
    }

    fn enabled_risk_config() -> RiskConfig {
        RiskConfig {
            enabled: true,
            ..RiskConfig::default()
        }
    }

    /// Threshold gate drives the returned decision: score-at-block → 403 with
    /// a `Phase::RiskScore` result, challenge band → Challenge, disabled
    /// config → Allow even with block-at-0 thresholds.
    #[tokio::test(flavor = "multi_thread")]
    async fn risk_threshold_matrix_enforced() {
        let (engine, _container) = spawn_engine().await;
        engine.replace_risk_config(enabled_risk_config());

        // Block: score 0 >= block threshold 0.
        let mut ctx = make_ctx_with_thresholds("/", "198.51.100.1", 0, 0);
        let decision = engine.inspect(&mut ctx).await;
        assert!(
            matches!(decision.action, WafAction::Block { status: 403, .. }),
            "block-at-0 thresholds must 403, got {:?}",
            decision.action
        );
        let result = decision.result.as_ref().expect("risk block must carry a result");
        assert_eq!(result.phase, waf_common::Phase::RiskScore);
        assert_eq!(result.rule_name, "cumulative_risk");

        // Challenge: score 0 in [allow=0, block=101).
        let mut ctx = make_ctx_with_thresholds("/", "198.51.100.2", 0, 101);
        let decision = engine.inspect(&mut ctx).await;
        assert!(
            matches!(decision.action, WafAction::Challenge),
            "challenge-band thresholds must challenge, got {:?}",
            decision.action
        );
        let result = decision.result.as_ref().expect("risk challenge must carry a result");
        assert_eq!(result.phase, waf_common::Phase::RiskScore);
        assert_eq!(result.rule_name, "cumulative_risk");

        // Disabled config short-circuits before the threshold gate.
        engine.replace_risk_config(RiskConfig::default());
        let mut ctx = make_ctx_with_thresholds("/", "198.51.100.3", 0, 0);
        let decision = engine.inspect(&mut ctx).await;
        assert!(
            matches!(decision.action, WafAction::Allow),
            "disabled risk config must not enforce, got {:?}",
            decision.action
        );
    }

    /// FR-028 canary contract: a canary hit 403s at `Phase::RiskScore` with
    /// score 100 (issue AC #2), IP-bans via the `DDoS` table so the follow-up
    /// request blocks at `Phase::Ddos`, and a directly pinned actor blocks
    /// through the threshold override (issue AC #3).
    #[tokio::test(flavor = "multi_thread")]
    async fn canary_hit_bans_and_pin_blocks() {
        use crate::checks::ddos::DdosTierCfg;
        use crate::risk::config::CanaryConfig;
        use waf_common::tier::Tier;

        let (engine, _container) = spawn_engine().await;
        // Default DdosConfig has no tiers → the ban-table check never runs.
        // Configure the CatchAll tier with unreachable burst thresholds so
        // only the ban lookup is active.
        engine.ddos_cfg.store(Arc::new(DdosConfig {
            tiers: HashMap::from([(
                Tier::CatchAll,
                DdosTierCfg {
                    per_fp_threshold: 1_000_000,
                    per_fp_window_s: 60,
                    per_tier_threshold: 1_000_000,
                    per_tier_window_s: 60,
                },
            )]),
            ..DdosConfig::default()
        }));
        engine.replace_risk_config(RiskConfig {
            canary: CanaryConfig {
                enabled: true,
                paths: vec!["/admin-test".to_string()],
                ban_ttl_secs: 600,
            },
            ..enabled_risk_config()
        });

        // Canary hit → real 403 at the engine boundary (issue AC #2).
        let mut ctx = make_ctx("risk-test", "/admin-test", "203.0.113.50");
        let decision = engine.inspect(&mut ctx).await;
        assert!(
            matches!(decision.action, WafAction::Block { status: 403, .. }),
            "canary hit must 403, got {:?}",
            decision.action
        );
        let result = decision.result.as_ref().expect("canary block must carry a result");
        assert_eq!(result.phase, waf_common::Phase::RiskScore);
        assert_eq!(result.rule_name, "cumulative_risk");
        assert_eq!(decision.risk_score, 100, "canary force-max must pin score to 100");

        // Same IP, normal path → blocked by the DDoS ban planted by the
        // canary hit (FR-028 ban-table contract; Phase 19 runs pre-scoring).
        let mut ctx = make_ctx("risk-test", "/", "203.0.113.50");
        let decision = engine.inspect(&mut ctx).await;
        assert!(
            matches!(decision.action, WafAction::Block { .. }),
            "banned canary IP must stay blocked, got {:?}",
            decision.action
        );
        let result = decision.result.as_ref().expect("ban block must carry a result");
        assert_eq!(
            result.phase,
            waf_common::Phase::Ddos,
            "post-canary block must come from the DDoS ban phase, not re-scoring"
        );

        // Different IP, pinned directly via force_max → threshold override
        // blocks even with default (permissive) thresholds (issue AC #3).
        let mut ctx = make_ctx("risk-test", "/", "203.0.113.51");
        let now_ms = chrono::Utc::now().timestamp_millis();
        engine
            .scorer
            .load()
            .force_max(&ctx, None, now_ms + 60_000, now_ms)
            .await
            .expect("force_max");
        let decision = engine.inspect(&mut ctx).await;
        assert!(
            matches!(decision.action, WafAction::Block { status: 403, .. }),
            "pinned actor must block via override, got {:?}",
            decision.action
        );
        let result = decision.result.as_ref().expect("pinned block must carry a result");
        assert_eq!(result.phase, waf_common::Phase::RiskScore);
        assert_eq!(result.rule_name, "cumulative_risk");
        assert_eq!(decision.risk_score, 100, "pinned actor must carry score 100");
    }

    /// Monitor mode on `risk_assessment` downgrades a risk block to `LogOnly`:
    /// the Block intent and `Phase::RiskScore` result are preserved for
    /// logging, but the request proceeds.
    #[tokio::test(flavor = "multi_thread")]
    async fn risk_block_respects_monitor_mode() {
        let (engine, _container) = spawn_engine().await;
        engine.replace_risk_config(enabled_risk_config());
        let mr = ModeRegistry::new();
        mr.set_feature("risk_assessment", InteropMode::LogOnly);
        engine.set_mode_registry(mr);

        let mut ctx = make_ctx_with_thresholds("/", "198.51.100.10", 0, 0);
        let decision = engine.inspect(&mut ctx).await;
        assert!(
            matches!(decision.action, WafAction::Block { .. }),
            "block intent must be preserved for logging, got {:?}",
            decision.action
        );
        assert_eq!(decision.mode, InteropMode::LogOnly);
        assert!(
            decision.is_enforcement_allowed(),
            "monitored risk block must let the request proceed"
        );
        let result = decision.result.as_ref().expect("monitored block must carry a result");
        assert_eq!(result.phase, waf_common::Phase::RiskScore);
        assert_eq!(result.rule_name, "cumulative_risk");
    }

    /// The escalation gate applies to plain-Allow decisions only: a pipeline
    /// detection — enforced or downgraded to `LogOnly` by a monitored feature —
    /// is never replaced by a risk escalation.
    #[tokio::test(flavor = "multi_thread")]
    async fn risk_never_overrides_pipeline_decisions() {
        let (engine, _container) = spawn_engine().await;
        engine.replace_risk_config(enabled_risk_config());

        // Enforced detection: SQLi block wins even at block-at-0 thresholds.
        let mut ctx = make_ctx_with_thresholds("/", "198.51.100.20", 0, 0);
        ctx.query = "id=1' OR '1'='1".into();
        let decision = engine.inspect(&mut ctx).await;
        assert!(
            matches!(decision.action, WafAction::Block { .. }),
            "SQLi payload must block, got {:?}",
            decision.action
        );
        let result = decision.result.as_ref().expect("SQLi block must carry a result");
        assert_eq!(
            result.phase,
            waf_common::Phase::SqlInjection,
            "enforced detection must keep its own phase, not Phase::RiskScore"
        );

        // LogOnly'd detection: with injection_control in monitor mode the
        // SQLi decision (mode LogOnly) is still returned — no risk escalation.
        let mr = ModeRegistry::new();
        mr.set_feature("injection_control", InteropMode::LogOnly);
        engine.set_mode_registry(mr);
        let mut ctx = make_ctx_with_thresholds("/", "198.51.100.21", 0, 0);
        ctx.query = "id=1' OR '1'='1".into();
        let decision = engine.inspect(&mut ctx).await;
        let result = decision.result.as_ref().expect("LogOnly'd SQLi must carry its result");
        assert_eq!(
            result.phase,
            waf_common::Phase::SqlInjection,
            "LogOnly'd detection must not be replaced by a risk escalation"
        );
        assert_eq!(decision.mode, InteropMode::LogOnly);
        assert!(
            decision.is_enforcement_allowed(),
            "LogOnly'd SQLi decision must let the request proceed"
        );
    }

    /// Default (memory) backend starts the purge loop: expired state is
    /// removed without any caller invoking `purge_expired`.
    #[tokio::test(flavor = "multi_thread")]
    async fn build_risk_store_memory_purges_expired_state() {
        use crate::risk::key::RiskKey;
        use crate::risk::state::{Contributor, ContributorKind, SeedKind};

        let cfg = RiskConfig {
            ttl_secs: 1,
            gc_interval_secs: 1,
            ..RiskConfig::default()
        };
        let store = WafEngine::build_risk_store(&cfg).await;

        let key = RiskKey::from_ip("198.51.100.77".parse().expect("ip"));
        let stale_ms = chrono::Utc::now().timestamp_millis() - 10_000;
        store
            .apply(
                &key,
                &[Contributor::new(ContributorKind::Seed(SeedKind::Generic), 25, stale_ms)],
                stale_ms,
            )
            .await
            .expect("apply");
        assert!(!store.is_empty().await, "state must exist before purge");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while std::time::Instant::now() < deadline {
            if store.is_empty().await {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("purge loop never removed expired state");
    }

    /// `store.backend: redis` without a reachable server falls back to the
    /// memory store (fail-soft); builds without the `redis-store` feature take
    /// the same fallback via the feature-gate warning path.
    #[tokio::test]
    async fn build_risk_store_redis_unreachable_falls_back_to_memory() {
        let mut cfg = RiskConfig::default();
        cfg.store.backend = "redis".to_string();
        cfg.store.redis.url = "redis://127.0.0.1:1".to_string();

        let store = WafEngine::build_risk_store(&cfg).await;
        assert!(store.is_empty().await, "fallback memory store must start empty");
    }

    /// `store.backend: redis` with a reachable server builds the redis store:
    /// applied state must be visible through the same store (CI redis job;
    /// skips when `REDIS_TEST_URL` is unset).
    #[cfg(feature = "redis-store")]
    #[tokio::test]
    async fn build_risk_store_redis_backend_persists_state() {
        let Ok(url) = std::env::var("REDIS_TEST_URL") else {
            return;
        };
        let now_ms = chrono::Utc::now().timestamp_millis();
        let mut cfg = RiskConfig::default();
        cfg.store.backend = "redis".to_string();
        cfg.store.redis.url = url;
        cfg.store.redis.key_prefix = format!("waf:risk:enginetest:{now_ms}:");

        let store = WafEngine::build_risk_store(&cfg).await;
        let key = crate::risk::key::RiskKey::from_ip("10.98.98.98".parse().unwrap());
        let bump = crate::risk::state::Contributor::new(
            crate::risk::state::ContributorKind::Signal("engine_test".to_string()),
            30,
            now_ms,
        );
        let result = store.apply(&key, &[bump], now_ms).await.expect("apply via redis store");
        assert_eq!(result.state.clamped_score, 30);
        let read = store.read(&key).await.expect("read via redis store");
        assert!(read.is_some(), "scored actor state must be visible in redis");
        store.clear(&key).await.expect("cleanup");
    }

    /// `start_risk_watcher`: initial load applies the file config, a file
    /// write hot-reloads the snapshot and resyncs the canary layer, and bad
    /// YAML keeps the previous snapshot (fail-soft).
    #[tokio::test(flavor = "multi_thread")]
    async fn risk_watcher_hot_reloads_config_and_canary() {
        let (engine, _container) = spawn_engine().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("risk.yaml");
        std::fs::write(&path, "risk:\n  enabled: false\n").expect("write initial");

        engine.start_risk_watcher(&path).await;
        assert!(!engine.risk_cfg.load().enabled, "initial config has enabled=false");

        std::fs::write(&path, "risk:\n  enabled: true\n  canary:\n    paths:\n      - /trap\n").expect("write update");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if engine.risk_cfg.load().enabled {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "hot reload never observed enabled=true"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            engine.risk_canary.check("/trap"),
            "reload must resync canary paths through replace_risk_config semantics"
        );

        // Malformed YAML: previous snapshot (and canary set) must be retained.
        std::fs::write(&path, "risk:\n  ttl_secs: not_a_number\n").expect("write bad yaml");
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        assert!(engine.risk_cfg.load().enabled, "bad YAML must keep previous snapshot");
        assert!(engine.risk_canary.check("/trap"), "bad YAML must keep canary paths");
    }
}
