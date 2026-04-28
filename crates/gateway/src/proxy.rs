//! Pingora [`ProxyHttp`] implementation that wires WAF inspection and filter
//! chains into the proxy lifecycle.
//!
//! All context construction is delegated to [`RequestCtxBuilder`].
//! All filter execution is delegated to [`RequestFilterChain`] /
//! [`ResponseFilterChain`] (populated by phases 02–04).
//! WAF response helpers live in [`super::proxy_waf_response`].

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use tracing::{debug, info, warn};

use pingora_core::upstreams::peer::HttpPeer;
use pingora_proxy::{ProxyHttp, Session};

use waf_engine::WafEngine;

use crate::context::{BODY_PREVIEW_LIMIT, GatewayCtx};
use crate::ctx_builder::RequestCtxBuilder;
use crate::pipeline::{FilterCtx, RequestFilterChain, ResponseFilterChain};
use crate::proxy_waf_response::{write_waf_body_decision, write_waf_decision};
use crate::router::HostRouter;

/// Pingora-based reverse proxy with WAF integration and filter chains.
pub struct WafProxy {
    pub router: Arc<HostRouter>,
    pub engine: Arc<WafEngine>,
    /// Whether to trust X-Forwarded-For headers for client IP extraction.
    pub trust_proxy_headers: bool,
    /// Parsed trusted proxy CIDR ranges.
    pub trusted_proxies: Vec<ipnet::IpNet>,
    /// Total request counter (cloned from `AppState`).
    pub request_counter: Arc<AtomicU64>,
    /// Blocked request counter (cloned from `AppState`).
    pub blocked_counter: Arc<AtomicU64>,
    /// Ordered chain of upstream request filters (populated by phases 02–04).
    pub request_chain: Arc<RequestFilterChain>,
    /// Ordered chain of response filters (populated by phases 02–03).
    pub response_chain: Arc<ResponseFilterChain>,
}

impl WafProxy {
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(router: Arc<HostRouter>, engine: Arc<WafEngine>) -> Self {
        Self {
            router,
            engine,
            trust_proxy_headers: false,
            trusted_proxies: Vec::new(),
            request_counter: Arc::new(AtomicU64::new(0)),
            blocked_counter: Arc::new(AtomicU64::new(0)),
            request_chain: Arc::new(RequestFilterChain::new()),
            response_chain: Arc::new(ResponseFilterChain::new()),
        }
    }
}

#[async_trait]
impl ProxyHttp for WafProxy {
    type CTX = GatewayCtx;

    fn new_ctx(&self) -> Self::CTX {
        GatewayCtx::default()
    }

    async fn upstream_peer(&self, session: &mut Session, ctx: &mut GatewayCtx) -> pingora_core::Result<Box<HttpPeer>> {
        self.request_counter.fetch_add(1, Ordering::Relaxed);

        let host_header = session
            .get_header("host")
            .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
            .unwrap_or("")
            .to_string();

        debug!("Routing request for host: {}", host_header);

        let host_config = self.router.resolve(&host_header).ok_or_else(|| {
            pingora_core::Error::explain(
                pingora_core::ErrorType::ConnectProxyFailure,
                format!("No route found for host: {host_header}"),
            )
        })?;

        if !host_config.start_status {
            return Err(pingora_core::Error::explain(
                pingora_core::ErrorType::ConnectProxyFailure,
                "Site is closed",
            ));
        }

        let upstream_addr = format!("{}:{}", host_config.remote_host, host_config.remote_port);
        let use_tls = host_config.ssl;

        ctx.upstream_addr = Some(upstream_addr.clone());
        if ctx.host_config.is_none() {
            ctx.host_config = Some(Arc::clone(&host_config));
        }
        if ctx.request_ctx.is_none() {
            ctx.request_ctx = Some(
                RequestCtxBuilder::new(session, self.trust_proxy_headers, &self.trusted_proxies)
                    .with_host_config(Arc::clone(&host_config))
                    .build(),
            );
        }

        info!("Proxying {} → {}", host_header, upstream_addr);
        Ok(Box::new(HttpPeer::new(
            &upstream_addr,
            use_tls,
            host_config.remote_host.clone(),
        )))
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut GatewayCtx) -> pingora_core::Result<bool> {
        // Build request context early so WAF runs before upstream_peer.
        if ctx.request_ctx.is_none() {
            let host_header = session
                .get_header("host")
                .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
                .unwrap_or("")
                .to_string();
            if let Some(host_config) = self.router.resolve(&host_header) {
                ctx.host_config = Some(Arc::clone(&host_config));
                ctx.request_ctx = Some(
                    RequestCtxBuilder::new(session, self.trust_proxy_headers, &self.trusted_proxies)
                        .with_host_config(host_config)
                        .build(),
                );
            }
        }

        let host_for_log = ctx
            .request_ctx
            .as_ref()
            .map_or_else(|| "<unknown>".to_string(), |c| c.host.clone());

        // FAIL-CLOSED: never bypass WAF when context is missing (AC-22).
        let mut request_ctx = if let Some(c) = &ctx.request_ctx {
            c.clone()
        } else {
            self.blocked_counter.fetch_add(1, Ordering::Relaxed);
            warn!(host = %host_for_log, "fail-closed: missing request context, returning 503");
            let response = pingora_http::ResponseHeader::build(503, None)?;
            session.write_response_header(Box::new(response), false).await?;
            session
                .write_response_body(Some(Bytes::from_static(b"Service Unavailable")), true)
                .await?;
            return Ok(true);
        };

        if request_ctx.path == "/health" && request_ctx.method == "GET" {
            let _ = session.respond_error(200).await;
            return Ok(true);
        }

        let decision = self.engine.inspect(&mut request_ctx).await;
        write_waf_decision(session, &decision, &request_ctx, &self.blocked_counter).await
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut GatewayCtx,
    ) -> pingora_core::Result<()> {
        if ctx.body_inspected {
            return Ok(());
        }
        if let Some(chunk) = body {
            let remaining = BODY_PREVIEW_LIMIT.saturating_sub(ctx.body_buf.len());
            if remaining > 0 {
                let take = chunk.len().min(remaining);
                if let Some(slice) = chunk.get(..take) {
                    ctx.body_buf.extend_from_slice(slice);
                }
            }
        }
        let should_inspect = ctx.body_buf.len() >= BODY_PREVIEW_LIMIT || (end_of_stream && !ctx.body_buf.is_empty());
        if !should_inspect {
            return Ok(());
        }
        ctx.body_inspected = true;
        let mut request_ctx = match &ctx.request_ctx {
            Some(c) => c.clone(),
            None => return Ok(()),
        };
        request_ctx.body_preview = Bytes::copy_from_slice(&ctx.body_buf);
        let decision = self.engine.inspect(&mut request_ctx).await;
        write_waf_body_decision(session, &decision, &request_ctx, &self.blocked_counter).await
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        if let (Some(req_ctx), Some(hc)) = (&ctx.request_ctx, &ctx.host_config) {
            let fctx = FilterCtx {
                request_ctx: req_ctx,
                host_config: hc,
                peer_ip: req_ctx.client_ip,
                is_tls: req_ctx.is_tls,
            };
            self.request_chain.apply_all(upstream_request, &fctx)?;
        }
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut pingora_http::ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        if let (Some(req_ctx), Some(hc)) = (&ctx.request_ctx, &ctx.host_config) {
            let fctx = FilterCtx {
                request_ctx: req_ctx,
                host_config: hc,
                peer_ip: req_ctx.client_ip,
                is_tls: req_ctx.is_tls,
            };
            self.response_chain.apply_all(upstream_response, &fctx)?;
        }
        Ok(())
    }

    async fn logging(&self, _session: &mut Session, _error: Option<&pingora_core::Error>, ctx: &mut GatewayCtx) {
        if let Some(req_ctx) = &ctx.request_ctx {
            debug!(
                "Request completed: {} {} {} → upstream={}",
                req_ctx.method,
                req_ctx.host,
                req_ctx.path,
                ctx.upstream_addr.as_deref().unwrap_or("unknown"),
            );
        }
    }
}
