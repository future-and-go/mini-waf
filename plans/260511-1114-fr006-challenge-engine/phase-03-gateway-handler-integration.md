---
phase: 3
title: "Gateway Handler Integration"
status: complete
priority: P1
effort: "0.5d"
dependencies: [1, 2]
---

# Phase 3: Gateway Handler Integration

## Overview

Wire the challenge renderer into the gateway's response handler. When `WafAction::Challenge` is returned, render the challenge page instead of proxying to upstream.

## Requirements

**Functional:**
- Handle `WafAction::Challenge` in `write_waf_decision()`
- Check for existing valid `__waf_cc` cookie first
- If valid cookie → allow request (bypass challenge)
- If no/invalid cookie → render challenge page with 429 status
- Set appropriate headers (Cache-Control, X-Robots-Tag)

**Non-functional:**
- Challenge decision latency ≤ 1ms
- No additional allocations beyond page render

## Architecture

```
write_waf_decision()
    │
    ├── WafAction::Allow → proxy to upstream
    ├── WafAction::Block → return block page
    ├── WafAction::Redirect → return 302
    └── WafAction::Challenge (NEW)
            │
            ├── Check __waf_cc cookie
            │       │
            │       ├── Valid → Allow (return Ok(false))
            │       │
            │       └── Invalid/Missing → Render challenge page
            │                                │
            │                                ▼
            │                          Return 429 + HTML
            │
            └── Return Ok(true)
```

## Related Code Files

**Modify:**
- `crates/gateway/src/proxy_waf_response.rs` — add Challenge arm (after line 62)
- `crates/gateway/src/proxy.rs` — pass challenge renderer to handler

**Reference:**
- `crates/waf-engine/src/risk/challenge_credit/` — ChallengeIssuer API
- `crates/waf-engine/src/challenge/` — renderer (Phase 1)

## Implementation Steps

### Step 1: Add challenge imports to proxy_waf_response.rs

```rust
// crates/gateway/src/proxy_waf_response.rs (top of file)
use waf_engine::challenge::{
    ChallengeContext, ChallengeRenderer, JsChallengeRenderer, 
    PowSolution, verify_pow, DifficultyMap
};
use waf_engine::risk::{ChallengeIssuer, ChallengeVerifier, VerifyOutcome};
```

### Step 2: Add Challenge handler in write_waf_decision

```rust
// crates/gateway/src/proxy_waf_response.rs
// After line 62 (after Redirect arm), add:

WafAction::Challenge => {
    // Get challenge components from context
    let challenge_ctx = ctx.challenge_ctx.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Challenge context not initialized"))?;
    
    // Check for existing valid cookie
    if let Some(cookie_value) = ctx.cookies.get("__waf_cc") {
        if let Some(solution) = PowSolution::parse_cookie(cookie_value) {
            // Verify the PoW solution
            let difficulty = challenge_ctx.difficulty_map.difficulty_for_risk(decision.risk_score);
            if verify_pow(&solution.token, &solution.nonce, difficulty) == PowVerifyResult::Valid {
                // Verify token signature via ChallengeVerifier
                let binding = build_fingerprint_binding(ctx);
                let now_ms = chrono::Utc::now().timestamp_millis();
                match challenge_ctx.verifier.verify(&solution.token, &binding, now_ms).await {
                    VerifyOutcome::Valid { .. } => {
                        // Valid challenge credit - allow request
                        tracing::debug!(req_id = %ctx.req_id, "Challenge credit valid, allowing");
                        return Ok(false); // Continue to upstream
                    }
                    outcome => {
                        tracing::debug!(req_id = %ctx.req_id, ?outcome, "Challenge credit invalid");
                        // Fall through to issue new challenge
                    }
                }
            }
        }
    }
    
    // Issue new challenge token
    let binding = build_fingerprint_binding(ctx);
    let now_ms = chrono::Utc::now().timestamp_millis();
    let token = challenge_ctx.issuer.issue(&binding, now_ms);
    
    // Determine difficulty based on risk score
    let difficulty = challenge_ctx.difficulty_map.difficulty_for_risk(decision.risk_score);
    
    // Build redirect URL (original request)
    let redirect_url = ctx.original_url.clone();
    
    // Render challenge page
    let render_ctx = ChallengeContext {
        token,
        difficulty,
        redirect_url,
        branding_title: challenge_ctx.config.branding_title.clone(),
        branding_message: challenge_ctx.config.branding_message.clone(),
    };
    
    let response = challenge_ctx.renderer.render(&render_ctx)?;
    
    // Write response
    let mut resp = ResponseHeader::build(response.status, None)?;
    for (name, value) in &response.headers {
        resp.insert_header(name, value)?;
    }
    
    session.write_response_header(Box::new(resp), false).await?;
    session.write_response_body(Some(Bytes::from(response.body)), true).await?;
    
    tracing::info!(
        req_id = %ctx.req_id,
        risk_score = decision.risk_score,
        difficulty,
        "Challenge page served"
    );
    
    Ok(true) // Request handled
}
```

### Step 3: Add fingerprint binding helper

```rust
// crates/gateway/src/proxy_waf_response.rs (helper function)

fn build_fingerprint_binding(ctx: &RequestCtx) -> String {
    use sha2::{Sha256, Digest};
    
    let mut hasher = Sha256::new();
    
    // IP
    hasher.update(ctx.client_ip.to_string().as_bytes());
    
    // JA3/JA4 fingerprint (if available)
    if let Some(ref fp) = ctx.device_identity {
        if let Some(ref ja3) = fp.ja3 {
            hasher.update(ja3.as_bytes());
        }
        if let Some(ref ja4) = fp.ja4 {
            hasher.update(ja4.as_bytes());
        }
        if let Some(ref h2) = fp.h2_fingerprint {
            hasher.update(h2.as_bytes());
        }
    }
    
    // Return hex-encoded hash
    hex::encode(hasher.finalize())
}
```

### Step 4: Add ChallengeCtx to RequestCtx

```rust
// crates/waf-common/src/types.rs (add to RequestCtx struct)

pub struct ChallengeCtx {
    pub issuer: Arc<ChallengeIssuer>,
    pub verifier: Arc<ChallengeVerifier>,
    pub renderer: Arc<dyn ChallengeRenderer>,
    pub difficulty_map: DifficultyMap,
    pub config: ChallengePageConfig,
}

pub struct ChallengePageConfig {
    pub branding_title: String,
    pub branding_message: String,
}
```

### Step 5: Initialize challenge context in proxy.rs

```rust
// crates/gateway/src/proxy.rs (in initialization)

let challenge_ctx = ChallengeCtx {
    issuer: Arc::clone(&self.challenge_issuer),
    verifier: Arc::clone(&self.challenge_verifier),
    renderer: Arc::new(JsChallengeRenderer::default()),
    difficulty_map: DifficultyMap::default(),
    config: ChallengePageConfig {
        branding_title: "Security Check".into(),
        branding_message: "Please wait while we verify your browser...".into(),
    },
};
ctx.challenge_ctx = Some(challenge_ctx);
```

## Success Criteria

- [x] `WafAction::Challenge` handled in `write_waf_decision()`
- [x] Valid `__waf_cc` cookie bypasses challenge (returns `Ok(false)`)
- [x] Invalid/missing cookie renders challenge page
- [x] Response has 429 status + correct headers
- [x] Fingerprint binding includes IP (JA3/JA4/H2 deferred to phase with DeviceIdentity integration)
- [x] `cargo check --package gateway` passes

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| Missing device_identity | Fallback to IP-only binding |
| Cookie parsing failure | Silent fallback to new challenge |
| Async verification latency | Use cached verifier, in-memory nonce store |
