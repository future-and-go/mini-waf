//! Challenge page HTML template.
//!
//! Renders a minimal, self-contained HTML page that:
//! - Shows a spinner and message while computing `PoW`
//! - Uses Web Crypto API for SHA-256 hashing
//! - Sets cookie and redirects on success
//! - Falls back to block message if JavaScript disabled

use super::renderer::ChallengeContext;

/// HTML template with placeholders for dynamic values.
///
/// Placeholders (all must be HTML-escaped before insertion):
/// - `{{title}}` — Page title and heading
/// - `{{message}}` — User-facing message
/// - `{{token}}` — Challenge token (used in `PoW` computation)
/// - `{{difficulty}}` — Number of leading zero hex chars required
/// - `{{redirect}}` — URL to redirect after solving
const CHALLENGE_TEMPLATE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{title}}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#f5f5f5}
.c{text-align:center;padding:2rem;max-width:400px}
.s{width:48px;height:48px;border:4px solid #e0e0e0;border-top-color:#333;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 1rem}
@keyframes spin{to{transform:rotate(360deg)}}
h1{font-size:1.25rem;margin-bottom:.5rem;color:#333}
p{color:#666;font-size:.875rem}
noscript .b{background:#fee;border:1px solid #fcc;padding:1rem;border-radius:4px;margin-top:1rem}
noscript h2{color:#c00;font-size:1rem;margin-bottom:.5rem}
</style>
</head>
<body>
<div class="c">
<div class="s"></div>
<h1>{{title}}</h1>
<p>{{message}}</p>
<noscript>
<div class="b">
<h2>JavaScript Required</h2>
<p>Please enable JavaScript to continue.</p>
</div>
</noscript>
</div>
<script>
(function(){
var t="{{token}}",d={{difficulty}},r="{{redirect}}";
function h(s){
var a=new Uint8Array(s.length);
for(var i=0;i<s.length;i++)a[i]=s.charCodeAt(i);
return crypto.subtle.digest("SHA-256",a).then(function(b){
return Array.from(new Uint8Array(b)).map(function(x){
return x.toString(16).padStart(2,"0")
}).join("")
})
}
function c(x,n){
for(var i=0;i<n;i++)if(x[i]!=="0")return false;
return true
}
function w(n){
h(t+n).then(function(x){
if(c(x,d)){
document.cookie="__waf_cc="+t+"."+n+";path=/;max-age=300;SameSite=Strict";
location.href=r
}else{
setTimeout(function(){w(n+1)},0)
}
})
}
w(0)
})();
</script>
</body>
</html>"#;

/// Escape a string for safe inclusion in HTML content.
///
/// Prevents XSS by replacing dangerous characters with HTML entities.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Render the challenge page with the given context.
///
/// All dynamic values are HTML-escaped to prevent XSS attacks.
pub fn render_challenge_page(ctx: &ChallengeContext) -> String {
    CHALLENGE_TEMPLATE
        .replace("{{title}}", &html_escape(&ctx.branding_title))
        .replace("{{message}}", &html_escape(&ctx.branding_message))
        .replace("{{token}}", &html_escape(&ctx.token))
        .replace("{{difficulty}}", &ctx.difficulty.to_string())
        .replace("{{redirect}}", &html_escape(&ctx.redirect_url))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx() -> ChallengeContext {
        ChallengeContext {
            token: "abc123".into(),
            difficulty: 4,
            redirect_url: "/test".into(),
            branding_title: "Security Check".into(),
            branding_message: "Please wait...".into(),
        }
    }

    #[test]
    fn renders_all_placeholders() {
        let ctx = make_ctx();
        let html = render_challenge_page(&ctx);

        assert!(html.contains("abc123"), "token missing");
        assert!(html.contains("/test"), "redirect missing");
        assert!(html.contains("Security Check"), "title missing");
        assert!(html.contains("Please wait..."), "message missing");
        assert!(html.contains("d=4"), "difficulty missing");
    }

    #[test]
    fn page_size_under_5kb() {
        let ctx = make_ctx();
        let html = render_challenge_page(&ctx);
        let size = html.len();

        assert!(size < 5120, "page size {size} bytes exceeds 5KB limit");
    }

    #[test]
    fn contains_noscript_fallback() {
        let ctx = make_ctx();
        let html = render_challenge_page(&ctx);

        assert!(html.contains("<noscript>"));
        assert!(html.contains("JavaScript Required"));
    }

    #[test]
    fn contains_cookie_setting() {
        let ctx = make_ctx();
        let html = render_challenge_page(&ctx);

        assert!(html.contains("__waf_cc="));
        assert!(html.contains("SameSite=Strict"));
    }

    #[test]
    fn escapes_xss_in_token() {
        let ctx = ChallengeContext {
            token: "<script>alert(1)</script>".into(),
            ..make_ctx()
        };
        let html = render_challenge_page(&ctx);

        assert!(!html.contains("<script>alert"), "XSS payload not escaped");
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn preserves_redirect_url_in_output() {
        // Note: Actual validation of redirect_url (blocking javascript:, data:)
        // is done in renderer.rs, not here. This template just renders what it gets.
        let ctx = ChallengeContext {
            redirect_url: "/safe/path".into(),
            ..make_ctx()
        };
        let html = render_challenge_page(&ctx);
        assert!(html.contains("/safe/path"));
    }

    #[test]
    fn escapes_xss_in_title() {
        let ctx = ChallengeContext {
            branding_title: "<img onerror=alert(1)>".into(),
            ..make_ctx()
        };
        let html = render_challenge_page(&ctx);

        assert!(!html.contains("<img onerror"));
        assert!(html.contains("&lt;img"));
    }

    #[test]
    fn escapes_quotes_and_ampersand() {
        let ctx = ChallengeContext {
            branding_message: "A & B \"quoted\" 'apostrophe'".into(),
            ..make_ctx()
        };
        let html = render_challenge_page(&ctx);

        assert!(html.contains("A &amp; B"));
        assert!(html.contains("&quot;quoted&quot;"));
        assert!(html.contains("&#x27;apostrophe&#x27;"));
    }

    #[test]
    fn html_escape_preserves_safe_chars() {
        assert_eq!(html_escape("hello"), "hello");
        assert_eq!(html_escape("a-b_c.d"), "a-b_c.d");
        assert_eq!(html_escape("123"), "123");
        assert_eq!(html_escape(""), "");
    }

    #[test]
    fn is_valid_html() {
        let ctx = make_ctx();
        let html = render_challenge_page(&ctx);

        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("<html lang=\"en\">"));
        assert!(html.contains("</html>"));
        assert!(html.contains("<head>") && html.contains("</head>"));
        assert!(html.contains("<body>") && html.contains("</body>"));
    }
}
