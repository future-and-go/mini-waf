---
phase: 1
title: "Challenge Page Renderer"
status: complete
priority: P1
effort: "1.5d"
dependencies: []
---

# Phase 1: Challenge Page Renderer

## Overview

Create the challenge module with HTML page renderer. Page must be minimal (<5KB), self-contained (inline CSS/JS), and render a user-friendly "security check" message with auto-solving PoW.

## Requirements

**Functional:**
- Render challenge page with embedded token and difficulty
- Auto-submit form on PoW solve
- Set `__waf_cc` cookie with solution token
- Redirect to original URL after solve
- NoScript fallback shows block message

**Non-functional:**
- Page size ≤ 5KB (fast load under DDoS)
- No external dependencies (CDN, fonts, images)
- XSS-safe via html_escape (follow block_page.rs pattern)

## Architecture

```
challenge/
├── mod.rs           # Module exports
├── renderer.rs      # ChallengeRenderer trait + JsChallengeRenderer
├── page_template.rs # HTML template string + render function
└── pow.rs           # (Phase 2) PoW algorithm
```

## Related Code Files

**Create:**
- `crates/waf-engine/src/challenge/mod.rs`
- `crates/waf-engine/src/challenge/renderer.rs`
- `crates/waf-engine/src/challenge/page_template.rs`

**Modify:**
- `crates/waf-engine/src/lib.rs` — add `pub mod challenge;`

**Reference (patterns to follow):**
- `crates/waf-engine/src/block_page.rs` — HTML template + escape pattern

## Implementation Steps

### Step 1: Create challenge module structure

```rust
// crates/waf-engine/src/challenge/mod.rs
mod renderer;
mod page_template;

pub use renderer::{ChallengeRenderer, JsChallengeRenderer, ChallengeContext, ChallengeResponse};
pub use page_template::render_challenge_page;
```

### Step 2: Define ChallengeContext and ChallengeResponse

```rust
// crates/waf-engine/src/challenge/renderer.rs
pub struct ChallengeContext {
    pub token: String,           // Challenge token from ChallengeIssuer
    pub difficulty: u8,          // PoW difficulty (leading zero bits)
    pub redirect_url: String,    // Original request URL
    pub branding_title: String,  // Configurable title
    pub branding_message: String,// Configurable message
}

pub struct ChallengeResponse {
    pub status: u16,             // 429 Too Many Requests
    pub body: String,            // HTML page
    pub headers: Vec<(String, String)>, // Cache-Control, X-Robots-Tag
}
```

### Step 3: Implement ChallengeRenderer trait

```rust
pub trait ChallengeRenderer: Send + Sync {
    fn render(&self, ctx: &ChallengeContext) -> Result<ChallengeResponse, ChallengeError>;
}

pub struct JsChallengeRenderer {
    pub difficulty_map: DifficultyMap,
}

impl ChallengeRenderer for JsChallengeRenderer {
    fn render(&self, ctx: &ChallengeContext) -> Result<ChallengeResponse, ChallengeError> {
        let html = render_challenge_page(ctx)?;
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
```

### Step 4: Create HTML template

```rust
// crates/waf-engine/src/challenge/page_template.rs
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
noscript .b{background:#fee;border:1px solid #fcc;padding:1rem;border-radius:4px}
</style>
</head>
<body>
<div class="c">
<div class="s"></div>
<h1>{{title}}</h1>
<p>{{message}}</p>
<noscript><div class="b"><h1>JavaScript Required</h1><p>Please enable JavaScript to continue.</p></div></noscript>
</div>
<script>
(function(){
var t="{{token}}",d={{difficulty}},r="{{redirect}}";
function h(s){var a=new Uint8Array(s.length);for(var i=0;i<s.length;i++)a[i]=s.charCodeAt(i);return crypto.subtle.digest("SHA-256",a).then(function(b){return Array.from(new Uint8Array(b)).map(function(x){return x.toString(16).padStart(2,"0")}).join("")})}
function c(x,n){for(var i=0;i<n;i++)if(x[i]!=="0")return false;return true}
function w(n){h(t+n).then(function(x){if(c(x,d/4)){document.cookie="__waf_cc="+t+"."+n+";path=/;max-age=300;SameSite=Strict";location.href=r}else{setTimeout(function(){w(n+1)},0)}})}
w(0)
})();
</script>
</body>
</html>"#;

pub fn render_challenge_page(ctx: &ChallengeContext) -> Result<String, ChallengeError> {
    let html = CHALLENGE_TEMPLATE
        .replace("{{title}}", &html_escape(&ctx.branding_title))
        .replace("{{message}}", &html_escape(&ctx.branding_message))
        .replace("{{token}}", &html_escape(&ctx.token))
        .replace("{{difficulty}}", &ctx.difficulty.to_string())
        .replace("{{redirect}}", &html_escape(&ctx.redirect_url));
    Ok(html)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}
```

### Step 5: Export from lib.rs

```rust
// crates/waf-engine/src/lib.rs (add line)
pub mod challenge;
```

### Step 6: Verify page size

```bash
# After implementation, verify:
echo '<rendered html>' | wc -c  # Must be < 5120 bytes
```

## Success Criteria

- [ ] `challenge/mod.rs` exports `ChallengeRenderer`, `JsChallengeRenderer`, `ChallengeContext`
- [ ] `render_challenge_page()` produces valid HTML
- [ ] HTML size < 5KB
- [ ] NoScript fallback shows block message
- [ ] `cargo check --package waf-engine` passes
- [ ] Template placeholders properly escaped (XSS safe)

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| XSS via token injection | Use `html_escape()` on all template vars |
| Template bloat | Keep CSS minimal, inline only |
| JS compatibility | Use ES5-compatible syntax, crypto.subtle fallback |
