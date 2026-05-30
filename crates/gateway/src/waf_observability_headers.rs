//! Contract-facing WAF observability response headers.

use pingora_http::ResponseHeader;

use crate::context::GatewayCtx;

const HEADER_REQUEST_ID: &str = "X-WAF-Request-Id";
const HEADER_RISK_SCORE: &str = "X-WAF-Risk-Score";
const HEADER_ACTION: &str = "X-WAF-Action";
const HEADER_RULE_ID: &str = "X-WAF-Rule-Id";
const HEADER_CACHE: &str = "X-WAF-Cache";
const HEADER_MODE: &str = "X-WAF-Mode";
const NONE: &str = "none";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CacheStatus {
    Hit,
    Miss,
    #[default]
    Bypass,
}

impl CacheStatus {
    #[must_use]
    pub const fn as_contract_str(self) -> &'static str {
        match self {
            Self::Hit => "HIT",
            Self::Miss => "MISS",
            Self::Bypass => "BYPASS",
        }
    }
}

pub struct WafHeaderValues<'a> {
    pub request_id: &'a str,
    pub risk_score: u8,
    pub action: &'a str,
    pub rule_id: Option<&'a str>,
    pub mode: &'a str,
    pub cache: CacheStatus,
}

pub fn inject_waf_observability_headers(
    resp: &mut ResponseHeader,
    vals: &WafHeaderValues<'_>,
) -> pingora_core::Result<()> {
    let risk_score = vals.risk_score.min(100).to_string();

    resp.insert_header(HEADER_REQUEST_ID, sanitize_request_id(vals.request_id))?;
    resp.insert_header(HEADER_RISK_SCORE, risk_score.as_str())?;
    resp.insert_header(HEADER_ACTION, sanitize_header_value(vals.action))?;
    resp.insert_header(HEADER_RULE_ID, sanitize_rule_id(vals.rule_id))?;
    resp.insert_header(HEADER_CACHE, vals.cache.as_contract_str())?;
    resp.insert_header(HEADER_MODE, sanitize_header_value(vals.mode))?;

    Ok(())
}

/// Inject the six contract observability headers on a passthrough / cache-HIT
/// response, sourcing values from the per-request [`GatewayCtx`] snapshot.
///
/// The `cache` field is read from `ctx.cache_status`. Caller (e.g.
/// `write_cached_entry`) sets that status to `Hit` before invoking; the
/// `response_filter` passthrough path leaves it at whatever
/// `request_filter` recorded (`Miss` for cache-fill, `Bypass` otherwise).
///
/// When `ctx.waf_decision_meta` is `None` (snapshot-None fallback that
/// should not occur after Phase 3 wires it on every outcome), the contract
/// demands all six headers still emit. We use safe defaults: `action=allow`,
/// `risk_score=0`, `rule_id=none`, and **derive `mode` from
/// `ctx.host_config.log_only_mode`** so we never hardcode `enforce`
/// (red-team F8).
pub fn inject_for_passthrough(resp: &mut ResponseHeader, ctx: &GatewayCtx) -> pingora_core::Result<()> {
    inject_for_passthrough_with_cache(resp, ctx, ctx.cache_status)
}

/// Variant of [`inject_for_passthrough`] that lets the caller override the
/// `X-WAF-Cache` value (e.g. [`crate::response_cache_integration::write_cached_entry`]
/// forces `Hit` regardless of the snapshot).
pub fn inject_for_passthrough_with_cache(
    resp: &mut ResponseHeader,
    ctx: &GatewayCtx,
    cache: CacheStatus,
) -> pingora_core::Result<()> {
    let req_id = ctx.request_ctx.as_ref().map_or(NONE, |r| r.req_id.as_str());
    let fallback_mode = ctx
        .host_config
        .as_ref()
        .map_or("enforce", |hc| if hc.log_only_mode { "log_only" } else { "enforce" });
    let (action, risk_score, rule_id, mode) = ctx
        .waf_decision_meta
        .as_ref()
        .map_or(("allow", 0u8, None, fallback_mode), |m| {
            (m.action, m.risk_score, m.rule_id.as_deref(), m.mode)
        });
    let values = WafHeaderValues {
        request_id: req_id,
        risk_score,
        action,
        rule_id,
        mode,
        cache,
    };
    inject_waf_observability_headers(resp, &values)
}

/// Inject the six contract headers on a pre-`inspect()` or error-page egress.
///
/// Covers access-gate 403, fail-closed 503, HTTP→HTTPS 301, health 200, and
/// transport 5xx via `fail_to_proxy`. No `WafDecision` snapshot is available
/// on these sites; the caller supplies the contract action string. The helper:
///
/// - reads `X-WAF-Request-Id` from `ctx.request_ctx.req_id` when present,
///   otherwise from `fallback_req_id` (caller-supplied fresh UUID v4 so the
///   wire header is never absent — §5↔§6 audit correlation),
/// - derives `X-WAF-Mode` from `ctx.host_config.log_only_mode` (never
///   hardcoded `enforce`),
/// - reuses `ctx.waf_decision_meta.risk_score` when an inspect already ran
///   (e.g. transport error AFTER `engine.inspect()`); otherwise `0`,
/// - hardcodes `X-WAF-Rule-Id: none` and `X-WAF-Cache: BYPASS` (these paths
///   bypass the response cache by definition).
pub fn inject_for_pre_inspect_or_error(
    resp: &mut ResponseHeader,
    ctx: &GatewayCtx,
    action: &str,
    fallback_req_id: &str,
) -> pingora_core::Result<()> {
    let req_id = ctx.request_ctx.as_ref().map_or(fallback_req_id, |r| r.req_id.as_str());
    let mode = ctx
        .host_config
        .as_ref()
        .map_or("enforce", |hc| if hc.log_only_mode { "log_only" } else { "enforce" });
    let risk_score = ctx.waf_decision_meta.as_ref().map_or(0, |m| m.risk_score);
    let values = WafHeaderValues {
        request_id: req_id,
        risk_score,
        action,
        rule_id: None,
        mode,
        cache: CacheStatus::Bypass,
    };
    inject_waf_observability_headers(resp, &values)
}

fn sanitize_request_id(request_id: &str) -> &str {
    if has_crlf(request_id) { NONE } else { request_id }
}

fn sanitize_rule_id(rule_id: Option<&str>) -> &str {
    rule_id.map_or(NONE, |value| {
        let stripped = value.trim();
        if is_valid_rule_id(stripped) { stripped } else { NONE }
    })
}

fn sanitize_header_value(value: &str) -> &str {
    if has_crlf(value) { NONE } else { value }
}

fn is_valid_rule_id(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(is_token_byte)
}

const fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        )
}

fn has_crlf(value: &str) -> bool {
    value.bytes().any(|byte| matches!(byte, b'\r' | b'\n'))
}
