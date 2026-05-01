use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Client;

/// Shared HTTP client for all community API interactions.
///
/// Centralises timeout, TLS, and base-URL configuration so that the
/// reporter, enrolller, and blocklist sync modules do not each build
/// their own `reqwest::Client`.
pub struct CommunityClient {
    pub(crate) http: Client,
    pub(crate) base_url: String,
}

impl CommunityClient {
    /// Create a new community client.
    ///
    /// The `base_url` should not contain a trailing slash.
    pub fn new(base_url: &str) -> Result<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("failed to build community HTTP client")?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
        })
    }

    /// Test connectivity to the community server by hitting the blocklist
    /// version endpoint. Returns a human-readable status message.
    pub async fn test_connection(&self, api_key: Option<&str>) -> Result<String> {
        let url = format!("{}/api/v1/waf/blocklist/version", self.base_url);
        let mut req = self.http.get(&url);
        if let Some(key) = api_key {
            req = req.bearer_auth(key);
        }

        let resp = req.send().await.context("community server connection test failed")?;

        let status = resp.status();
        if status.is_success() {
            Ok(format!("Connected to community server at {}", self.base_url))
        } else {
            anyhow::bail!("community server returned {status}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_strips_trailing_slashes() {
        let c = CommunityClient::new("https://example.com///").expect("client");
        assert_eq!(c.base_url, "https://example.com");
    }

    #[test]
    fn new_keeps_clean_url_unchanged() {
        let c = CommunityClient::new("https://example.com").expect("client");
        assert_eq!(c.base_url, "https://example.com");
    }

    #[tokio::test]
    async fn test_connection_unreachable_host_returns_error() {
        // Use a TCP port that should reject immediately (loopback, no listener).
        let c = CommunityClient::new("http://127.0.0.1:1").expect("client");
        let res = c.test_connection(Some("k")).await;
        assert!(res.is_err());
    }
}
