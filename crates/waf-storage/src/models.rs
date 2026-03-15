use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Host / site configuration
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

/// Attack log entry
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
    pub created_at: DateTime<Utc>,
}

/// Create host request
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
    pub start_status: bool,
    pub log_only_mode: bool,
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
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}
