//! Contract-facing WAF observability response headers.

use pingora_http::ResponseHeader;

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
