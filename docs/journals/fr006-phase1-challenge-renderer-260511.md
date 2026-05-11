# FR-006 Phase 1: Challenge Page Renderer — Complete

**Date**: 2026-05-11 12:29
**Severity**: Medium
**Component**: `crates/waf-engine/src/challenge` (new module)
**Status**: Resolved

## What Happened

Implemented the HTML page renderer for Challenge Engine Phase 1. This page displays a spinner and auto-solves a JavaScript Proof-of-Work challenge to mitigate bot attacks. Three files created (~230 LoC total): trait definition, renderer, and HTML template.

## The Brutal Truth

This worked cleanly because the attack surface is narrow and well-understood. No unexpected issues. The hardest part wasn't the code — it was remembering that **HTML escaping doesn't protect JavaScript string context**. That distinction almost got missed.

## Technical Details

**Files:**
- `renderer.rs` (130 lines) — `ChallengeRenderer` trait + `JsChallengeRenderer` impl
- `page_template.rs` (110 lines) — HTML template + `html_escape()` utility
- `mod.rs` (11 lines) — exports

**Page size:** 1.7 KB (well under 5 KB DDoS resilience target)

**Key implementation choices:**
- ES5 JavaScript (no arrow functions, const, let) for legacy browser compatibility
- Web Crypto API (`crypto.subtle.digest("SHA-256")`) — built-in, no external deps
- Token validation: `[a-zA-Z0-9_-]` only — prevents newlines and quotes that break JS strings
- URL validation: must start with `/`, `http://`, or `https://` — blocks `javascript:` and `data:` URIs

**Security gates (validated before template render):**
1. Empty token rejected
2. Token charset restricted (alphanumeric + dash/underscore)
3. Difficulty range 1–32 enforced
4. Redirect URL scheme whitelist (prevents XSS via `location.href`)

## What We Tried

No pivots needed. Straightforward trait + template pattern. The validator logic was built in from the start (not added as afterthought).

## Root Cause Analysis

Why it worked: scope was tight (single HTML page, no external dependencies), security model was explicit upfront (whitelist before render, not hope-and-escape), and the attack vectors were minimal (only token, difficulty, redirect URL exposed to user input).

## Lessons Learned

**Critical lesson**: HTML entity escaping (`&lt;`, `&quot;`, `&#x27;`) protects HTML context only. JavaScript string context is different — a `"` inside a JS string that was HTML-escaped as `&quot;` is still a literal `"` character *after* the HTML parser decodes it. The validator must catch dangerous characters *before* they enter the JS code.

**Pattern that worked**: Whitelist validation > blacklist. Allowing only `[a-zA-Z0-9_-]` in token is bulletproof because there's no character that breaks a JS string literal — you can't inject code with alphanumerics alone.

**15 unit tests** (11 original + 4 security-focused):
- Empty token, invalid difficulty, unsafe chars in token (newline, backslash, quote)
- `javascript:` and `data:` URI rejection
- Valid URL acceptance (relative, http, https)
- XSS escaping (title, message, token all tested)
- Page size and valid HTML structure

**Zero cargo warnings.** No unwrap(), no panics, proper error types.

## Next Steps

1. **Phase 2 (blocking)**: Implement `ChallengeIssuer` trait + `JsChallengeIssuer` — generates token + difficulty, stores state
2. **Phase 3 (blocking)**: Middleware integration — hook into request/response pipeline to serve challenge page on rate-limit trigger
3. **Phase 4**: Token validation endpoint — verify PoW solution on retry

File location: `/Users/thuocnguyen/Documents/personal-workspace/mini-waf/crates/waf-engine/src/challenge/`
