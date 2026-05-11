//! FR-006 — Challenge renderer integration tests.
//!
//! Tests the full rendering pipeline: ChallengeContext → JsChallengeRenderer → HTML output.
//! Focuses on integration scenarios not covered by inline unit tests.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::missing_docs_in_private_items
)]

use waf_engine::challenge::{
    ChallengeConfig, ChallengeContext, ChallengeRenderer, JsChallengeRenderer, render_challenge_page,
};

fn make_ctx(token: &str, difficulty: u8, redirect: &str) -> ChallengeContext {
    ChallengeContext {
        token: token.into(),
        difficulty,
        redirect_url: redirect.into(),
        branding_title: "Security Check".into(),
        branding_message: "Verifying your browser...".into(),
    }
}

#[test]
fn render_challenge_page_contains_all_required_elements() {
    let ctx = make_ctx("test_token_abc123", 4, "/original-path");
    let html = render_challenge_page(&ctx);

    assert!(html.contains("test_token_abc123"), "token missing");
    assert!(html.contains("d=4"), "difficulty parameter missing");
    assert!(html.contains("/original-path"), "redirect URL missing");
    assert!(html.contains("Security Check"), "branding title missing");
    assert!(html.contains("Verifying your browser"), "branding message missing");
    assert!(html.contains("<noscript>"), "noscript fallback missing");
    assert!(html.contains("JavaScript Required"), "noscript message missing");
    assert!(html.contains("__waf_cc="), "cookie name missing");
}

#[test]
fn renderer_trait_produces_correct_response_structure() {
    let renderer = JsChallengeRenderer::new();
    let ctx = make_ctx("trait-test-token", 6, "/test");

    let resp = renderer.render(&ctx).expect("render should succeed");

    assert_eq!(resp.status, 429, "challenge must return 429 status");
    assert!(resp.body.contains("trait-test-token"), "token not in body");
    assert!(
        resp.headers
            .iter()
            .any(|(k, v)| k == "Cache-Control" && v.contains("no-store"))
    );
    assert!(resp.headers.iter().any(|(k, v)| k == "X-Robots-Tag" && v == "noindex"));
    assert!(
        resp.headers
            .iter()
            .any(|(k, v)| k == "Content-Type" && v.contains("text/html"))
    );
}

#[test]
fn page_size_stays_under_5kb_with_realistic_values() {
    let ctx = ChallengeContext {
        token: "abcdefgh12345678".into(),
        difficulty: 16,
        redirect_url: "https://example.com/very/long/path/to/some/resource?query=value&foo=bar".into(),
        branding_title: "Company Security Verification".into(),
        branding_message: "Please wait while we verify that you're not a bot. This usually takes just a few seconds."
            .into(),
    };

    let html = render_challenge_page(&ctx);
    let size = html.len();
    assert!(size < 5120, "page size {size} bytes exceeds 5KB limit");
}

#[test]
fn xss_escape_handles_all_dangerous_chars() {
    let ctx = ChallengeContext {
        token: "safe-token".into(),
        difficulty: 4,
        redirect_url: "/test".into(),
        branding_title: "<script>alert('XSS')</script>".into(),
        branding_message: "<img src=x onerror='alert(1)'> & \"quotes\" 'apostrophe'".into(),
    };

    let html = render_challenge_page(&ctx);

    assert!(!html.contains("<script>alert"), "script tag not escaped");
    assert!(!html.contains("<img src=x onerror"), "img onerror not escaped");
    assert!(html.contains("&lt;script&gt;"), "script should be entity-escaped");
    assert!(html.contains("&amp;"), "ampersand should be escaped");
    assert!(html.contains("&quot;"), "quotes should be escaped");
    assert!(html.contains("&#x27;"), "apostrophe should be escaped");
}

#[test]
fn renderer_validates_token_format() {
    let renderer = JsChallengeRenderer::new();

    let invalid_tokens = [
        ("", "empty token"),
        ("has\nnewline", "newline in token"),
        ("has\\backslash", "backslash in token"),
        ("has\"quote", "quote in token"),
        ("has'apostrophe", "apostrophe in token"),
        ("has<bracket", "angle bracket in token"),
        ("has>bracket", "angle bracket in token"),
        ("has&ampersand", "ampersand in token"),
    ];

    for (token, desc) in invalid_tokens {
        let ctx = make_ctx(token, 4, "/test");
        let result = renderer.render(&ctx);
        assert!(result.is_err(), "{desc} should be rejected");
    }
}

#[test]
fn renderer_validates_difficulty_bounds() {
    let renderer = JsChallengeRenderer::new();

    let ctx_zero = make_ctx("token", 0, "/");
    assert!(renderer.render(&ctx_zero).is_err(), "difficulty 0 should fail");

    let ctx_high = make_ctx("token", 33, "/");
    assert!(renderer.render(&ctx_high).is_err(), "difficulty 33 should fail");

    for d in [1, 16, 32] {
        let ctx = make_ctx("token", d, "/");
        assert!(renderer.render(&ctx).is_ok(), "difficulty {d} should succeed");
    }
}

#[test]
fn renderer_rejects_dangerous_redirect_urls() {
    let renderer = JsChallengeRenderer::new();

    let dangerous_urls = [
        ("javascript:alert(1)", "javascript URI"),
        ("data:text/html,<script>alert(1)</script>", "data URI"),
        ("vbscript:MsgBox(1)", "vbscript URI"),
        ("file:///etc/passwd", "file URI"),
    ];

    for (url, desc) in dangerous_urls {
        let ctx = make_ctx("token", 4, url);
        assert!(renderer.render(&ctx).is_err(), "{desc} should be rejected");
    }
}

#[test]
fn renderer_accepts_safe_redirect_urls() {
    let renderer = JsChallengeRenderer::new();

    let safe_urls = [
        "/relative/path",
        "/",
        "/path?query=1&foo=bar",
        "http://example.com/page",
        "https://example.com/page",
        "https://sub.example.com:8080/path",
    ];

    for url in safe_urls {
        let ctx = make_ctx("token", 4, url);
        assert!(renderer.render(&ctx).is_ok(), "URL '{url}' should be accepted");
    }
}

#[test]
fn html_output_is_well_formed() {
    let ctx = make_ctx("wellformed-test", 8, "/path");
    let html = render_challenge_page(&ctx);

    assert!(html.starts_with("<!DOCTYPE html>"), "missing doctype");
    assert!(html.contains("<html lang=\"en\">"), "missing html tag");
    assert!(html.contains("</html>"), "unclosed html tag");

    assert!(
        html.contains("<head>") && html.contains("</head>"),
        "missing head section"
    );
    assert!(
        html.contains("<body>") && html.contains("</body>"),
        "missing body section"
    );
    assert!(
        html.contains("<script>") && html.contains("</script>"),
        "missing script section"
    );

    assert!(html.contains("<meta charset=\"utf-8\">"), "missing charset meta");
    assert!(html.contains("<meta name=\"viewport\""), "missing viewport meta");
}

#[test]
fn rendered_page_contains_pow_algorithm() {
    let ctx = make_ctx("pow-algo-test", 12, "/verify");
    let html = render_challenge_page(&ctx);

    assert!(html.contains("crypto.subtle.digest"), "missing Web Crypto API call");
    assert!(html.contains("SHA-256"), "missing SHA-256 reference");
    assert!(html.contains("d=12"), "difficulty not embedded in script");
}

#[test]
fn config_branding_flows_to_rendered_page() {
    let cfg = ChallengeConfig::default();
    let ctx = ChallengeContext {
        token: "config-test".into(),
        difficulty: cfg.difficulty.default,
        redirect_url: "/".into(),
        branding_title: cfg.branding.title.clone(),
        branding_message: cfg.branding.message.clone(),
    };

    let html = render_challenge_page(&ctx);

    assert!(html.contains(&cfg.branding.title), "config title not in page");
    assert!(html.contains(&cfg.branding.message), "config message not in page");
}

#[test]
fn default_context_renders_successfully() {
    let mut ctx = ChallengeContext::default();
    ctx.token = "default-ctx-token".into();

    let renderer = JsChallengeRenderer::new();
    let result = renderer.render(&ctx);
    assert!(result.is_ok(), "default context should render");
}
