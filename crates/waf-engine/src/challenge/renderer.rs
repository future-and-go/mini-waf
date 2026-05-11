//! Challenge renderer trait and JS-based implementation.

use super::page_template::render_challenge_page;
use std::fmt;

/// Context passed to the challenge renderer.
#[derive(Debug, Clone)]
pub struct ChallengeContext {
    /// Challenge token from `ChallengeIssuer` (Phase 2)
    pub token: String,
    /// `PoW` difficulty — number of leading zero hex characters required in hash
    pub difficulty: u8,
    /// Original request URL to redirect after solving
    pub redirect_url: String,
    /// Configurable page title (default: "Security Check")
    pub branding_title: String,
    /// Configurable message shown to user
    pub branding_message: String,
}

impl Default for ChallengeContext {
    fn default() -> Self {
        Self {
            token: String::new(),
            difficulty: 4,
            redirect_url: "/".to_string(),
            branding_title: "Security Check".to_string(),
            branding_message: "Verifying your browser, please wait...".to_string(),
        }
    }
}

/// Response from challenge renderer.
#[derive(Debug, Clone)]
pub struct ChallengeResponse {
    /// HTTP status code (429 for rate-limit challenge)
    pub status: u16,
    /// Rendered HTML body
    pub body: String,
    /// Response headers (Cache-Control, X-Robots-Tag, Content-Type)
    pub headers: Vec<(String, String)>,
}

/// Errors that can occur during challenge rendering.
#[derive(Debug)]
pub enum ChallengeError {
    /// Template rendering failed
    RenderError(String),
    /// Invalid configuration
    InvalidConfig(String),
}

impl fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RenderError(msg) => write!(f, "challenge render error: {msg}"),
            Self::InvalidConfig(msg) => write!(f, "challenge config error: {msg}"),
        }
    }
}

impl std::error::Error for ChallengeError {}

/// Trait for rendering challenge pages.
///
/// Different implementations can provide different challenge types:
/// - `JsChallengeRenderer` — JavaScript `PoW` (this phase)
/// - Future: CAPTCHA, hCaptcha, Turnstile integrations
pub trait ChallengeRenderer: Send + Sync {
    /// Render a challenge page for the given context.
    fn render(&self, ctx: &ChallengeContext) -> Result<ChallengeResponse, ChallengeError>;
}

/// JavaScript-based Proof-of-Work challenge renderer.
///
/// Renders a page that:
/// 1. Shows a spinner and "verifying" message
/// 2. Computes SHA-256 hashes until finding one with `difficulty` leading zeros
/// 3. Sets `__waf_cc` cookie with the solution
/// 4. Redirects to original URL
#[derive(Debug, Default)]
pub struct JsChallengeRenderer;

impl JsChallengeRenderer {
    pub const fn new() -> Self {
        Self
    }
}

impl ChallengeRenderer for JsChallengeRenderer {
    fn render(&self, ctx: &ChallengeContext) -> Result<ChallengeResponse, ChallengeError> {
        if ctx.token.is_empty() {
            return Err(ChallengeError::InvalidConfig("token cannot be empty".into()));
        }
        // Validate token contains only safe characters (prevents JS string injection)
        if !ctx
            .token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(ChallengeError::InvalidConfig(
                "token must be alphanumeric with dashes/underscores only".into(),
            ));
        }
        if ctx.difficulty == 0 || ctx.difficulty > 32 {
            return Err(ChallengeError::InvalidConfig("difficulty must be 1-32".into()));
        }
        // Validate redirect_url to prevent javascript: and data: URI attacks
        let url = ctx.redirect_url.trim();
        if !url.starts_with('/') && !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(ChallengeError::InvalidConfig(
                "redirect_url must be relative path or http(s) URL".into(),
            ));
        }

        let html = render_challenge_page(ctx);

        Ok(ChallengeResponse {
            status: 429,
            body: html,
            headers: vec![
                ("Cache-Control".into(), "no-store, no-cache, must-revalidate".into()),
                ("X-Robots-Tag".into(), "noindex".into()),
                ("Content-Type".into(), "text/html; charset=utf-8".into()),
            ],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_valid_challenge() {
        let renderer = JsChallengeRenderer::new();
        let ctx = ChallengeContext {
            token: "test-token-123".into(),
            difficulty: 4,
            redirect_url: "/original".into(),
            ..Default::default()
        };

        let resp = renderer.render(&ctx).expect("should render");
        assert_eq!(resp.status, 429);
        assert!(resp.body.contains("test-token-123"));
        assert!(resp.body.contains("/original"));
        assert!(resp.headers.iter().any(|(k, _)| k == "Cache-Control"));
    }

    #[test]
    fn rejects_empty_token() {
        let renderer = JsChallengeRenderer::new();
        let ctx = ChallengeContext {
            token: String::new(),
            ..Default::default()
        };

        let err = renderer.render(&ctx).unwrap_err();
        assert!(matches!(err, ChallengeError::InvalidConfig(_)));
    }

    #[test]
    fn rejects_invalid_difficulty() {
        let renderer = JsChallengeRenderer::new();

        let ctx_zero = ChallengeContext {
            token: "t".into(),
            difficulty: 0,
            ..Default::default()
        };
        assert!(renderer.render(&ctx_zero).is_err());

        let ctx_high = ChallengeContext {
            token: "t".into(),
            difficulty: 33,
            ..Default::default()
        };
        assert!(renderer.render(&ctx_high).is_err());
    }

    #[test]
    fn rejects_token_with_unsafe_chars() {
        let renderer = JsChallengeRenderer::new();

        // Newline breaks JS string
        let ctx_newline = ChallengeContext {
            token: "abc\ndef".into(),
            ..Default::default()
        };
        assert!(renderer.render(&ctx_newline).is_err());

        // Backslash can escape quotes
        let ctx_backslash = ChallengeContext {
            token: "abc\\def".into(),
            ..Default::default()
        };
        assert!(renderer.render(&ctx_backslash).is_err());

        // Quotes break JS string
        let ctx_quote = ChallengeContext {
            token: "abc\"def".into(),
            ..Default::default()
        };
        assert!(renderer.render(&ctx_quote).is_err());
    }

    #[test]
    fn rejects_javascript_uri() {
        let renderer = JsChallengeRenderer::new();
        let ctx = ChallengeContext {
            token: "valid-token".into(),
            redirect_url: "javascript:alert(1)".into(),
            ..Default::default()
        };
        let err = renderer.render(&ctx).unwrap_err();
        assert!(matches!(err, ChallengeError::InvalidConfig(_)));
    }

    #[test]
    fn rejects_data_uri() {
        let renderer = JsChallengeRenderer::new();
        let ctx = ChallengeContext {
            token: "valid-token".into(),
            redirect_url: "data:text/html,<script>alert(1)</script>".into(),
            ..Default::default()
        };
        assert!(renderer.render(&ctx).is_err());
    }

    #[test]
    fn accepts_valid_redirect_urls() {
        let renderer = JsChallengeRenderer::new();

        // Relative path
        let ctx_rel = ChallengeContext {
            token: "t".into(),
            redirect_url: "/path/to/page".into(),
            ..Default::default()
        };
        assert!(renderer.render(&ctx_rel).is_ok());

        // HTTP URL
        let ctx_http = ChallengeContext {
            token: "t".into(),
            redirect_url: "http://example.com/page".into(),
            ..Default::default()
        };
        assert!(renderer.render(&ctx_http).is_ok());

        // HTTPS URL
        let ctx_https = ChallengeContext {
            token: "t".into(),
            redirect_url: "https://example.com/page".into(),
            ..Default::default()
        };
        assert!(renderer.render(&ctx_https).is_ok());
    }
}
