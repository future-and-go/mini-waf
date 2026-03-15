use serde::{Deserialize, Serialize};

/// Top-level application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub proxy: ProxyConfig,
    pub api: ApiConfig,
    pub storage: StorageConfig,
    #[serde(default)]
    pub hosts: Vec<HostEntry>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            proxy: ProxyConfig::default(),
            api: ApiConfig::default(),
            storage: StorageConfig::default(),
            hosts: Vec::new(),
        }
    }
}

/// Proxy listener configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub listen_addr: String,
    pub listen_addr_tls: String,
    pub worker_threads: Option<usize>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:80".to_string(),
            listen_addr_tls: "0.0.0.0:443".to_string(),
            worker_threads: None,
        }
    }
}

/// Management API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    pub listen_addr: String,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:9527".to_string(),
        }
    }
}

/// Database storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub database_url: String,
    pub max_connections: u32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            database_url: "postgresql://prx_waf:prx_waf@127.0.0.1:5432/prx_waf".to_string(),
            max_connections: 20,
        }
    }
}

/// Static host entry from configuration file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostEntry {
    pub host: String,
    pub port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    pub ssl: Option<bool>,
    pub guard_status: Option<bool>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
}

/// Load configuration from a TOML file
pub fn load_config(path: &str) -> anyhow::Result<AppConfig> {
    let content = std::fs::read_to_string(path)?;
    let config: AppConfig = toml::from_str(&content)?;
    Ok(config)
}
