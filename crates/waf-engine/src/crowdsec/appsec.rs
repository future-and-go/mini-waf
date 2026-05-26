use anyhow::{Context, Result};
use reqwest::Client;
use std::time::Duration;
use tracing::{debug, warn};

use waf_common::{DetectionResult, Phase, RequestCtx};

use super::circuit_breaker::AppSecCircuitBreaker;
use super::config::AppSecConfig;
use super::models::AppSecResponse;

/// Result of an `AppSec` check
#[derive(Debug, Clone)]
pub enum AppSecResult {
    /// Request is clean — allow it
    Allow,
    /// Request is malicious — block it
    Block { message: String },
    /// `AppSec` engine unavailable — caller applies `fallback_action`
    Unavailable,
}

/// `CrowdSec` `AppSec` protocol client.
///
/// Implements the `CrowdSec` `AppSec` protocol: forward each request to the
/// `AppSec` HTTP endpoint using special headers, then act on the response.
/// A circuit breaker prevents cascade failures when the endpoint is down.
pub struct AppSecClient {
    client: Client,
    config: AppSecConfig,
    circuit_breaker: AppSecCircuitBreaker,
}

impl AppSecClient {
    pub fn new(config: AppSecConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .build()
            .context("failed to build AppSec HTTP client")?;
        let circuit_breaker =
            AppSecCircuitBreaker::new(config.circuit_breaker_threshold, config.circuit_breaker_reset_secs);
        Ok(Self {
            client,
            config,
            circuit_breaker,
        })
    }

    /// Check a request against the `CrowdSec` `AppSec` engine.
    ///
    /// Returns `AppSecResult::Unavailable` when the circuit breaker is open
    /// or on network/timeout errors so that the caller can apply the
    /// configured `failure_action`.
    pub async fn check_request(&self, ctx: &RequestCtx) -> AppSecResult {
        if !self.circuit_breaker.check_allow() {
            warn!("AppSec circuit breaker OPEN; returning fallback");
            return AppSecResult::Unavailable;
        }
        match self.check_request_inner(ctx).await {
            Ok(AppSecResult::Unavailable) => {
                // HTTP 401/500/bad-status returns Ok(Unavailable) — treat as failure
                // so persistent server errors trip the circuit.
                self.circuit_breaker.on_failure();
                AppSecResult::Unavailable
            }
            Ok(result) => {
                self.circuit_breaker.on_success();
                result
            }
            Err(e) => {
                warn!("AppSec check error: {}", e);
                self.circuit_breaker.on_failure();
                AppSecResult::Unavailable
            }
        }
    }

    async fn check_request_inner(&self, ctx: &RequestCtx) -> Result<AppSecResult> {
        let http_version = "HTTP/1.1";

        let mut builder = self
            .client
            .post(&self.config.endpoint)
            .header("X-Crowdsec-Appsec-Ip", ctx.client_ip.to_string())
            .header("X-Crowdsec-Appsec-Uri", &ctx.path)
            .header("X-Crowdsec-Appsec-Host", &ctx.host)
            .header("X-Crowdsec-Appsec-Verb", &ctx.method)
            .header("X-Crowdsec-Appsec-Api-Key", &self.config.api_key)
            .header("X-Crowdsec-Appsec-Http-Version", http_version);

        if let Some(ua) = ctx.headers.get("user-agent") {
            builder = builder.header("X-Crowdsec-Appsec-User-Agent", ua);
        }

        // Forward body for methods that carry one
        let builder = if ctx.body_preview.is_empty() {
            builder
        } else {
            builder.body(ctx.body_preview.clone())
        };

        let resp = builder.send().await.context("AppSec HTTP request failed")?;
        let status = resp.status().as_u16();
        debug!("AppSec response status: {}", status);

        match status {
            200 => Ok(AppSecResult::Allow),
            403 => {
                let body: Option<AppSecResponse> = resp.json().await.ok();
                let message = body
                    .and_then(|b| b.message)
                    .unwrap_or_else(|| "blocked by CrowdSec AppSec".to_string());
                Ok(AppSecResult::Block { message })
            }
            401 => anyhow::bail!("AppSec authentication failed — check API key"),
            _ => {
                warn!("AppSec unexpected status {}", status);
                Ok(AppSecResult::Unavailable)
            }
        }
    }
}

/// Convert an `AppSec` block result into a WAF `DetectionResult`.
pub fn appsec_to_detection(message: String) -> DetectionResult {
    DetectionResult {
        rule_id: Some("crowdsec:appsec".to_string()),
        rule_name: "CrowdSec AppSec".to_string(),
        phase: Phase::CrowdSec,
        detail: message,
        rule_action: None,
        action_status: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crowdsec::config::FallbackAction;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::sync::Arc;
    use waf_common::HostConfig;

    fn cfg() -> AppSecConfig {
        AppSecConfig {
            endpoint: "http://127.0.0.1:1/appsec".to_string(),
            api_key: "k".to_string(),
            timeout_ms: 200,
            failure_action: FallbackAction::Allow,
            circuit_breaker_threshold: 5,
            circuit_breaker_reset_secs: 30,
        }
    }

    fn ctx() -> RequestCtx {
        RequestCtx {
            req_id: "t".to_string(),
            client_ip: "1.2.3.4".parse().expect("ip"),
            client_port: 0,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: "/".to_string(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config: Arc::new(HostConfig::default()),
            geo: None,
            tier: waf_common::tier::Tier::CatchAll,
            tier_policy: RequestCtx::default_tier_policy(),
            cookies: HashMap::new(),
        }
    }

    #[test]
    fn appsec_to_detection_carries_message() {
        let det = appsec_to_detection("blocked-by-appsec".to_string());
        assert_eq!(det.rule_id.as_deref(), Some("crowdsec:appsec"));
        assert_eq!(det.detail, "blocked-by-appsec");
        assert_eq!(det.phase, Phase::CrowdSec);
    }

    #[tokio::test]
    async fn check_request_returns_unavailable_when_endpoint_down() {
        let client = AppSecClient::new(cfg()).expect("client");
        let result = client.check_request(&ctx()).await;
        assert!(matches!(result, AppSecResult::Unavailable));
    }

    #[tokio::test]
    async fn check_request_forwards_body_when_present() {
        let client = AppSecClient::new(cfg()).expect("client");
        let mut c = ctx();
        c.body_preview = Bytes::from_static(b"some body");
        c.headers.insert("user-agent".to_string(), "test-agent".to_string());
        // Endpoint is unreachable — we just exercise the body branch.
        let result = client.check_request(&c).await;
        assert!(matches!(result, AppSecResult::Unavailable));
    }

    #[tokio::test]
    async fn circuit_breaker_opens_after_repeated_failures() {
        let mut config = cfg();
        config.circuit_breaker_threshold = 2;
        let client = AppSecClient::new(config).expect("client");
        let c = ctx();
        // First 2 requests hit the unreachable endpoint and fail.
        let _ = client.check_request(&c).await;
        let _ = client.check_request(&c).await;
        // Third request should be short-circuited by the circuit breaker
        // (no HTTP call, immediate Unavailable).
        let start = std::time::Instant::now();
        let result = client.check_request(&c).await;
        let elapsed = start.elapsed();
        assert!(matches!(result, AppSecResult::Unavailable));
        // Circuit-breaker short-circuit should be near-instant (< 5ms),
        // much faster than the 200ms timeout.
        assert!(
            elapsed < Duration::from_millis(50),
            "expected fast short-circuit, took {elapsed:?}",
        );
    }
}
