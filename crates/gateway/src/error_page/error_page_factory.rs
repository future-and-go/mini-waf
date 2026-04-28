//! Content-negotiated error-page renderer (AC-19).
//!
//! Negotiation by `Accept` header:
//! - contains `application/json` → `{"error":"<reason>","status":<n>}`
//! - otherwise → `text/plain` with a single-line reason
//!
//! Constraints (security):
//! - Body never echoes any request data (XSS-safe by construction).
//! - Response **never** sets `Server` — it is explicitly removed after build
//!   so the renderer can be used inside `fail_to_proxy` without leaking
//!   "Pingora" or any other intermediary fingerprint.

use bytes::Bytes;
use pingora_http::ResponseHeader;

/// Renders neutral error responses for both `fail_to_proxy` and the
/// fail-closed branch in [`crate::proxy::WafProxy::request_filter`].
pub struct ErrorPageFactory;

impl ErrorPageFactory {
    /// Build a `(headers, body)` tuple for the given status code, content-negotiated by `accept`.
    pub fn render(status: u16, accept: Option<&str>) -> pingora_core::Result<(ResponseHeader, Bytes)> {
        let reason = reason_for(status);
        let wants_json = accept.is_some_and(|a| a.to_ascii_lowercase().contains("application/json"));

        let (body, content_type) = if wants_json {
            let payload = format!("{{\"error\":\"{reason}\",\"status\":{status}}}");
            (Bytes::from(payload), "application/json; charset=utf-8")
        } else {
            (Bytes::from(reason.to_string()), "text/plain; charset=utf-8")
        };

        let mut headers = ResponseHeader::build(status, None).map_err(|e| {
            pingora_core::Error::because(pingora_core::ErrorType::InternalError, "build error header", e)
        })?;
        headers
            .insert_header("content-type", content_type)
            .map_err(|e| pingora_core::Error::because(pingora_core::ErrorType::InternalError, "set content-type", e))?;
        headers
            .insert_header("content-length", body.len().to_string().as_str())
            .map_err(|e| {
                pingora_core::Error::because(pingora_core::ErrorType::InternalError, "set content-length", e)
            })?;
        // Explicit scrub: defends against Pingora-injected defaults at h1/h2 layer.
        let _ = headers.remove_header("server");
        let _ = headers.remove_header("via");

        Ok((headers, body))
    }
}

const fn reason_for(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_branch_when_accept_contains_json() {
        let (h, body) = ErrorPageFactory::render(502, Some("application/json, text/plain")).expect("render");
        assert_eq!(
            h.headers.get("content-type").unwrap().as_bytes(),
            b"application/json; charset=utf-8"
        );
        assert_eq!(body.as_ref(), br#"{"error":"Bad Gateway","status":502}"#);
        assert!(h.headers.get("server").is_none(), "no server fingerprint");
        assert!(h.headers.get("via").is_none());
    }

    #[test]
    fn plain_branch_when_accept_missing() {
        let (h, body) = ErrorPageFactory::render(503, None).expect("render");
        assert_eq!(
            h.headers.get("content-type").unwrap().as_bytes(),
            b"text/plain; charset=utf-8"
        );
        assert_eq!(body.as_ref(), b"Service Unavailable");
    }

    #[test]
    fn plain_branch_when_accept_html_only() {
        let (h, _) = ErrorPageFactory::render(504, Some("text/html")).expect("render");
        assert_eq!(
            h.headers.get("content-type").unwrap().as_bytes(),
            b"text/plain; charset=utf-8"
        );
    }

    #[test]
    fn unknown_status_falls_back_to_generic() {
        let (_, body) = ErrorPageFactory::render(599, None).expect("render");
        assert_eq!(body.as_ref(), b"Error");
    }

    #[test]
    fn content_length_matches_body() {
        let (h, body) = ErrorPageFactory::render(502, None).expect("render");
        let cl = std::str::from_utf8(h.headers.get("content-length").unwrap().as_bytes())
            .unwrap()
            .parse::<usize>()
            .unwrap();
        assert_eq!(cl, body.len());
    }
}
