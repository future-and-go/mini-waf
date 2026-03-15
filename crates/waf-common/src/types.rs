use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

/// Request context passed through the WAF pipeline
#[derive(Debug, Clone)]
pub struct RequestCtx {
    pub req_id: String,
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub method: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub query: String,
    pub headers: HashMap<String, String>,
    pub body_preview: Bytes,
    pub content_length: u64,
    pub is_tls: bool,
    pub host_config: Arc<HostConfig>,
}

/// WAF action decision
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WafAction {
    Allow,
    Block {
        status: u16,
        body: Option<String>,
    },
    LogOnly,
    Redirect {
        url: String,
    },
}

/// WAF decision with context
#[derive(Debug, Clone)]
pub struct WafDecision {
    pub action: WafAction,
    pub result: Option<DetectionResult>,
}

impl WafDecision {
    pub fn allow() -> Self {
        Self {
            action: WafAction::Allow,
            result: None,
        }
    }

    pub fn block(status: u16, body: Option<String>, result: DetectionResult) -> Self {
        Self {
            action: WafAction::Block { status, body },
            result: Some(result),
        }
    }

    pub fn is_allowed(&self) -> bool {
        matches!(self.action, WafAction::Allow | WafAction::LogOnly)
    }
}

/// Detection phase
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Phase {
    IpWhitelist = 1,
    IpBlacklist = 2,
    UrlWhitelist = 3,
    UrlBlacklist = 4,
}

impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Phase::IpWhitelist => write!(f, "IP Whitelist"),
            Phase::IpBlacklist => write!(f, "IP Blacklist"),
            Phase::UrlWhitelist => write!(f, "URL Whitelist"),
            Phase::UrlBlacklist => write!(f, "URL Blacklist"),
        }
    }
}

/// Detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub rule_id: Option<String>,
    pub rule_name: String,
    pub phase: Phase,
    pub detail: String,
}

/// Host configuration matching SamWaf Hosts model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostConfig {
    pub code: String,
    pub host: String,
    pub port: u16,
    pub ssl: bool,
    pub guard_status: bool,
    pub remote_host: String,
    pub remote_port: u16,
    pub remote_ip: Option<String>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub remarks: Option<String>,
    pub start_status: bool,
    pub exclude_url_log: Vec<String>,
    pub is_enable_load_balance: bool,
    pub load_balance_strategy: LoadBalanceStrategy,
    pub defense_config: DefenseConfig,
    pub log_only_mode: bool,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            code: String::new(),
            host: String::new(),
            port: 80,
            ssl: false,
            guard_status: true,
            remote_host: String::new(),
            remote_port: 8080,
            remote_ip: None,
            cert_file: None,
            key_file: None,
            remarks: None,
            start_status: true,
            exclude_url_log: Vec::new(),
            is_enable_load_balance: false,
            load_balance_strategy: LoadBalanceStrategy::RoundRobin,
            defense_config: DefenseConfig::default(),
            log_only_mode: false,
        }
    }
}

/// Load balancing strategy
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalanceStrategy {
    #[default]
    RoundRobin,
    IpHash,
    WeightedRoundRobin,
}

/// Defense configuration per host
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenseConfig {
    pub bot: bool,
    pub sqli: bool,
    pub xss: bool,
    pub scan: bool,
    pub rce: bool,
    pub sensitive: bool,
    pub dir_traversal: bool,
    pub owasp_set: bool,
}

impl Default for DefenseConfig {
    fn default() -> Self {
        Self {
            bot: true,
            sqli: true,
            xss: true,
            scan: true,
            rce: true,
            sensitive: true,
            dir_traversal: true,
            owasp_set: false,
        }
    }
}
