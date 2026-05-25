use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Host / site configuration
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Host {
    pub id: Uuid,
    pub code: String,
    pub host: String,
    pub port: i32,
    pub ssl: bool,
    pub guard_status: bool,
    pub remote_host: String,
    pub remote_port: i32,
    pub remote_ip: Option<String>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub remarks: Option<String>,
    pub start_status: bool,
    pub exclude_url_log: Option<String>,
    pub is_enable_load_balance: bool,
    pub load_balance_stage: i32,
    pub defense_json: Option<serde_json::Value>,
    pub log_only_mode: bool,
    pub upstream_alpn: String,
    pub upstream_skip_ssl_verify: bool,
    /// Graceful degradation: defaults to `false` when the column is absent
    /// (e.g. binary deployed before migration 0016 has run).
    #[sqlx(default)]
    pub http_redirect: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// IP allowlist entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AllowIp {
    pub id: Uuid,
    pub host_code: String,
    pub ip_cidr: String,
    pub remarks: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// IP blocklist entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct BlockIp {
    pub id: Uuid,
    pub host_code: String,
    pub ip_cidr: String,
    pub remarks: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// URL allowlist entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AllowUrl {
    pub id: Uuid,
    pub host_code: String,
    pub url_pattern: String,
    pub match_type: String,
    pub remarks: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// URL blocklist entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct BlockUrl {
    pub id: Uuid,
    pub host_code: String,
    pub url_pattern: String,
    pub match_type: String,
    pub remarks: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Attack log entry (Phase 1 — IP / URL blacklist hits)
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AttackLog {
    pub id: Uuid,
    pub host_code: String,
    pub host: String,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub rule_id: Option<String>,
    pub rule_name: String,
    pub action: String,
    pub phase: String,
    pub detail: Option<String>,
    pub request_headers: Option<serde_json::Value>,
    pub geo_info: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

/// Security event entry (Phase 2 — attack detection)
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SecurityEvent {
    pub id: Uuid,
    pub host_code: String,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub rule_id: Option<String>,
    pub rule_name: String,
    pub action: String,
    pub detail: Option<String>,
    pub geo_info: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

/// SSL Certificate entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Certificate {
    pub id: Uuid,
    pub host_code: String,
    pub domain: String,
    pub cert_pem: Option<String>,
    pub key_pem: Option<String>,
    pub chain_pem: Option<String>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub auto_renew: bool,
    pub acme_account: Option<serde_json::Value>,
    pub status: String,
    pub error_msg: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Custom WAF rule entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CustomRule {
    pub id: Uuid,
    pub host_code: String,
    pub name: String,
    pub description: Option<String>,
    pub priority: i32,
    pub enabled: bool,
    pub condition_op: String,
    pub conditions: serde_json::Value,
    pub action: String,
    pub action_status: i32,
    pub action_msg: Option<String>,
    pub script: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// FR-025: Risk score delta when this rule matches.
    #[serde(default)]
    #[sqlx(default)]
    pub risk_delta: Option<i16>,
    /// FR-025: Override action for risk scoring ("block" forces immediate block).
    #[serde(default)]
    #[sqlx(default)]
    pub risk_action: Option<String>,
}

/// Sensitive pattern entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SensitivePattern {
    pub id: Uuid,
    pub host_code: String,
    pub pattern: String,
    pub pattern_type: String,
    pub check_request: bool,
    pub check_response: bool,
    pub action: String,
    pub remarks: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Hotlink configuration entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct HotlinkConfig {
    pub id: Uuid,
    pub host_code: String,
    pub enabled: bool,
    pub allow_empty_referer: bool,
    pub allowed_domains: serde_json::Value,
    pub redirect_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Load balancer backend entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct LbBackend {
    pub id: Uuid,
    pub host_code: String,
    pub backend_host: String,
    pub backend_port: i32,
    pub weight: i32,
    pub enabled: bool,
    pub health_check_url: Option<String>,
    pub health_check_interval_secs: i32,
    pub last_health_check: Option<DateTime<Utc>>,
    pub is_healthy: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ─── Request / Input types ────────────────────────────────────────────────────

/// Create host request
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateHost {
    pub host: String,
    pub port: i32,
    pub ssl: bool,
    pub guard_status: bool,
    pub remote_host: String,
    pub remote_port: i32,
    pub remote_ip: Option<String>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub remarks: Option<String>,
    #[serde(default)]
    pub start_status: bool,
    #[serde(default)]
    pub log_only_mode: bool,
    /// Upstream ALPN strategy. Canonical string values: `"h1_only"`,
    /// `"h2h1"`, `"h2_only"`. Defaults to `"h2h1"` when omitted.
    #[serde(default = "default_upstream_alpn")]
    pub upstream_alpn: String,
    /// Skip TLS certificate verification for the upstream. Default `false`.
    #[serde(default)]
    pub upstream_skip_ssl_verify: bool,
    /// Redirect plain-HTTP requests to HTTPS. Default `false`.
    #[serde(default)]
    pub http_redirect: bool,
    /// Per-host defense overrides (JSONB blob). When `None`, system defaults apply.
    /// Shape mirrors a partial `waf_common::DefenseConfig`; unknown keys ignored,
    /// missing keys fall back to defaults at engine load.
    #[serde(default)]
    pub defense_json: Option<serde_json::Value>,
}

fn default_upstream_alpn() -> String {
    "h2h1".to_string()
}

/// Update host request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateHost {
    pub host: Option<String>,
    pub port: Option<i32>,
    pub ssl: Option<bool>,
    pub guard_status: Option<bool>,
    pub remote_host: Option<String>,
    pub remote_port: Option<i32>,
    pub remote_ip: Option<String>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub remarks: Option<String>,
    pub start_status: Option<bool>,
    pub log_only_mode: Option<bool>,
    pub upstream_alpn: Option<String>,
    pub upstream_skip_ssl_verify: Option<bool>,
    pub http_redirect: Option<bool>,
    pub defense_json: Option<serde_json::Value>,
}

/// Create IP rule request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateIpRule {
    pub host_code: String,
    pub ip_cidr: String,
    pub remarks: Option<String>,
}

/// Create URL rule request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUrlRule {
    pub host_code: String,
    pub url_pattern: String,
    pub match_type: String,
    pub remarks: Option<String>,
}

/// Attack log query parameters
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AttackLogQuery {
    pub host_code: Option<String>,
    pub client_ip: Option<String>,
    pub action: Option<String>,
    pub country: Option<String>,
    pub iso_code: Option<String>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

/// Create security event (used internally by the engine)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSecurityEvent {
    pub host_code: String,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub rule_id: Option<String>,
    pub rule_name: String,
    pub action: String,
    pub detail: Option<String>,
    pub geo_info: Option<serde_json::Value>,
}

/// Security event query parameters
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityEventQuery {
    pub host_code: Option<String>,
    pub client_ip: Option<String>,
    pub rule_name: Option<String>,
    pub rule_id: Option<String>,
    // PATCH 1: prefix-based rule_id filter — matches rule_id ILIKE 'prefix%'
    pub rule_id_prefix: Option<String>,
    pub path: Option<String>,
    pub action: Option<String>,
    pub country: Option<String>,
    pub iso_code: Option<String>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

/// Create custom rule request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCustomRule {
    pub host_code: String,
    pub name: String,
    pub description: Option<String>,
    pub priority: Option<i32>,
    pub enabled: Option<bool>,
    pub condition_op: Option<String>,
    /// Flat legacy conditions array.  Ignored when `match_tree` is also set.
    #[serde(default)]
    pub conditions: serde_json::Value,
    /// Preferred: structured condition tree.  Packed as `{"match_tree": …}`
    /// in the `conditions` DB column, same convention as `UpdateCustomRule`.
    pub match_tree: Option<serde_json::Value>,
    pub action: Option<String>,
    pub action_status: Option<i32>,
    pub action_msg: Option<String>,
    pub script: Option<String>,
}

// ── Double-option deserializer ────────────────────────────────────────────────
// Distinguishes three JSON states for nullable string columns:
//   absent field  → None          (keep existing DB value)
//   explicit null → Some(None)    (write NULL to DB)
//   string value  → Some(Some(v)) (write new value to DB)
#[allow(clippy::option_option)]
fn deser_opt_null<'de, D, T>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Ok(Some(Option::deserialize(de)?))
}

/// Partial-update custom rule request (all fields optional for PATCH/PUT)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateCustomRule {
    pub host_code: Option<String>,
    pub name: Option<String>,
    /// `None` = keep, `Some(None)` = set NULL, `Some(Some(v))` = set value.
    #[serde(default, deserialize_with = "deser_opt_null")]
    pub description: Option<Option<String>>,
    pub priority: Option<i32>,
    pub enabled: Option<bool>,
    pub condition_op: Option<String>,
    /// Raw conditions array or pre-packed `{"match_tree": ...}` object.
    pub conditions: Option<serde_json::Value>,
    /// If present, overrides `conditions` — packed as `{"match_tree": ...}` before storage.
    pub match_tree: Option<serde_json::Value>,
    pub action: Option<String>,
    pub action_status: Option<i32>,
    /// `None` = keep, `Some(None)` = set NULL, `Some(Some(v))` = set value.
    #[serde(default, deserialize_with = "deser_opt_null")]
    pub action_msg: Option<Option<String>>,
    /// `None` = keep, `Some(None)` = set NULL, `Some(Some(v))` = set value.
    #[serde(default, deserialize_with = "deser_opt_null")]
    pub script: Option<Option<String>>,
}

/// Create sensitive pattern request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSensitivePattern {
    pub host_code: String,
    pub pattern: String,
    pub pattern_type: Option<String>,
    pub check_request: Option<bool>,
    pub check_response: Option<bool>,
    pub action: Option<String>,
    pub remarks: Option<String>,
}

/// Create/update hotlink config request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertHotlinkConfig {
    pub host_code: String,
    pub enabled: Option<bool>,
    pub allow_empty_referer: Option<bool>,
    pub allowed_domains: Option<Vec<String>>,
    pub redirect_url: Option<String>,
}

/// Create LB backend request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateLbBackend {
    pub host_code: String,
    pub backend_host: String,
    pub backend_port: i32,
    pub weight: Option<i32>,
    pub enabled: Option<bool>,
    pub health_check_url: Option<String>,
    pub health_check_interval_secs: Option<i32>,
}

/// Update certificate PEM data (issued by ACME or manual upload)
#[derive(Debug, Clone)]
pub struct UpdateCertificatePem<'a> {
    pub id: Uuid,
    pub cert_pem: &'a str,
    pub key_pem: &'a str,
    pub chain_pem: Option<&'a str>,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub issuer: &'a str,
    pub subject: &'a str,
}

/// Create certificate request (manual upload)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCertificate {
    pub host_code: String,
    pub domain: String,
    pub cert_pem: Option<String>,
    pub key_pem: Option<String>,
    pub chain_pem: Option<String>,
    pub auto_renew: Option<bool>,
}

// ─── Phase 4: Auth ────────────────────────────────────────────────────────────

/// Admin user
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AdminUser {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub role: String,
    pub is_active: bool,
    #[serde(skip_serializing)]
    pub totp_secret: Option<String>,
    pub totp_enabled: bool,
    pub last_login: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Refresh token entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
    pub created_at: DateTime<Utc>,
}

/// Create admin user request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAdminUser {
    pub username: String,
    pub email: Option<String>,
    pub password: String,
    pub role: Option<String>,
}

// ─── Phase 4: Statistics ──────────────────────────────────────────────────────

/// Aggregated request statistics row
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RequestStat {
    pub id: Uuid,
    pub host_code: String,
    pub period_start: DateTime<Utc>,
    pub period_type: String,
    pub total_requests: i64,
    pub blocked_requests: i64,
    pub allowed_requests: i64,
    pub stats_json: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Stats overview (aggregated from existing tables)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsOverview {
    pub total_requests: i64,
    pub total_blocked: i64,
    pub total_allowed: i64,
    pub hosts_count: i64,
    pub top_ips: Vec<TopEntry>,
    pub top_rules: Vec<TopEntry>,
    pub top_countries: Vec<TopEntry>,
    pub top_isps: Vec<TopEntry>,
    /// Distinct client IPs seen in `security_events`.
    pub unique_attackers: i64,
    /// Events grouped by attack category derived from `rule_id` prefix.
    pub category_breakdown: Vec<TopEntry>,
    /// Events grouped by enforcement action (block / log / allow / challenge).
    pub action_breakdown: Vec<TopEntry>,
    /// Last N security events for the recent activity feed.
    pub recent_events: Vec<RecentEvent>,
}

/// Compact security event entry for the dashboard live feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentEvent {
    pub ts: DateTime<Utc>,
    pub client_ip: String,
    pub host_code: String,
    pub method: String,
    pub path: String,
    pub rule_id: Option<String>,
    pub rule_name: String,
    pub action: String,
    pub category: String,
    pub country: Option<String>,
}

/// `GeoIP` distribution statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoStats {
    pub top_countries: Vec<TopEntry>,
    pub top_cities: Vec<TopEntry>,
    pub top_isps: Vec<TopEntry>,
    pub country_distribution: Vec<GeoDistEntry>,
}

/// `GeoIP` country distribution entry (for map visualization)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoDistEntry {
    pub iso_code: String,
    pub country: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopEntry {
    pub key: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesPoint {
    pub ts: DateTime<Utc>,
    pub total: i64,
    pub blocked: i64,
}

/// Per-category time-bucket from `security_events`, used by the Rule Analytics
/// stacked timeline chart.
///
/// `ts` is bucketed to the hour boundary; `category` is derived inline by the
/// same `CASE rule_id LIKE …` expression already shared with
/// `get_stats_overview` and `RecentEvent.category` so the dashboard does not
/// need a second mapping table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryTimeSeriesPoint {
    pub ts: DateTime<Utc>,
    pub category: String,
    pub count: i64,
}

// ─── Phase 4: Notifications ───────────────────────────────────────────────────

/// Notification configuration entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct NotificationConfig {
    pub id: Uuid,
    pub name: String,
    pub host_code: Option<String>,
    pub event_type: String,
    pub channel_type: String,
    pub config_json: serde_json::Value,
    pub enabled: bool,
    pub rate_limit_secs: i32,
    pub last_triggered: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Notification log entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct NotificationLog {
    pub id: Uuid,
    pub config_id: Option<Uuid>,
    pub event_type: String,
    pub channel_type: String,
    pub status: String,
    pub message: Option<String>,
    pub error_msg: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Create notification config request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNotificationConfig {
    pub name: String,
    pub host_code: Option<String>,
    pub event_type: String,
    pub channel_type: String,
    pub config_json: serde_json::Value,
    pub enabled: Option<bool>,
    pub rate_limit_secs: Option<i32>,
}

// ─── Phase 5: WASM Plugins ────────────────────────────────────────────────────

/// WASM plugin metadata (binary is stored separately)
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct WasmPluginRow {
    pub id: Uuid,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub author: Option<String>,
    pub wasm_binary: Vec<u8>,
    pub enabled: bool,
    pub config_json: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Create WASM plugin request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateWasmPlugin {
    pub name: String,
    pub version: Option<String>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub wasm_binary: Vec<u8>,
    pub enabled: Option<bool>,
    pub config_json: Option<serde_json::Value>,
}

// ─── Phase 5: Tunnels ─────────────────────────────────────────────────────────

/// Tunnel configuration row
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct TunnelRow {
    pub id: Uuid,
    pub name: String,
    pub token_hash: String,
    pub target_host: String,
    pub target_port: i32,
    pub enabled: bool,
    pub status: String,
    pub last_seen: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Create tunnel request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTunnel {
    pub name: String,
    /// Plain-text pre-shared key; will be hashed before storage
    pub token: String,
    pub target_host: String,
    pub target_port: i32,
    pub enabled: Option<bool>,
}

// ─── Phase 5: Audit Log ───────────────────────────────────────────────────────

/// Admin audit log entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AuditLogEntry {
    pub id: i64,
    pub admin_username: Option<String>,
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub detail: Option<serde_json::Value>,
    pub ip_addr: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Query parameters for audit log listing
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditLogQuery {
    pub admin_username: Option<String>,
    pub action: Option<String>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

// ─── Phase 6: CrowdSec ────────────────────────────────────────────────────────

/// `CrowdSec` integration configuration stored in database
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CrowdSecConfigRow {
    pub id: i32,
    pub host_id: Option<Uuid>,
    pub enabled: bool,
    pub mode: String,
    pub lapi_url: Option<String>,
    /// AES-256-GCM encrypted API key (base64 encoded)
    pub api_key_encrypted: Option<String>,
    pub appsec_endpoint: Option<String>,
    /// AES-256-GCM encrypted `AppSec` API key (base64 encoded)
    pub appsec_key_encrypted: Option<String>,
    pub update_frequency_secs: i32,
    pub fallback_action: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Upsert `CrowdSec` config request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertCrowdSecConfig {
    pub host_id: Option<Uuid>,
    pub enabled: bool,
    pub mode: String,
    pub lapi_url: Option<String>,
    /// Plaintext API key (will be encrypted before storage)
    pub api_key: Option<String>,
    pub appsec_endpoint: Option<String>,
    /// Plaintext `AppSec` API key (will be encrypted before storage)
    pub appsec_key: Option<String>,
    pub update_frequency_secs: Option<i32>,
    pub fallback_action: Option<String>,
}

/// A persisted `CrowdSec` event / detection log
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CrowdSecEventRow {
    pub id: i64,
    pub host_id: Option<Uuid>,
    pub client_ip: Option<String>,
    pub decision_type: Option<String>,
    pub scenario: Option<String>,
    pub action_taken: Option<String>,
    pub request_path: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Insert a new `CrowdSec` event
#[derive(Debug, Clone)]
pub struct CreateCrowdSecEvent {
    pub host_id: Option<Uuid>,
    pub client_ip: String,
    pub decision_type: String,
    pub scenario: String,
    pub action_taken: String,
    pub request_path: Option<String>,
}

/// Query params for listing `CrowdSec` events
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CrowdSecEventQuery {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

// ─── FR-030: Dashboard heatmap + stats filter ─────────────────────────────────

/// Single cell in the endpoint attack-heatmap (path × category).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeatmapCell {
    pub path: String,
    pub category: String,
    pub count: i64,
}

/// Full heatmap response: sparse cells + window metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointHeatmap {
    pub cells: Vec<HeatmapCell>,
    pub total_events: i64,
    pub paths_sampled: i64,
    pub categories_total: i64,
    pub window_hours: i64,
    pub generated_at: DateTime<Utc>,
}

/// Query parameters for `get_endpoint_heatmap`.
/// `hours` is clamped 1..=720 by the caller before passing in.
#[derive(Debug, Clone, Default)]
pub struct HeatmapFilter {
    pub hours: i64,
    pub host_code: Option<String>,
    pub action: Option<String>,
}

/// Optional filter for `get_stats_overview`.
/// All fields `None` ⇒ identical output to the pre-filter implementation
/// (full backward-compat guarantee).
#[derive(Debug, Clone, Default)]
pub struct StatsFilter {
    /// Restrict to events within the last N hours. `None` = all-time.
    pub hours: Option<i64>,
    pub host_code: Option<String>,
    pub action: Option<String>,
}
