---
phase: 5
title: "Unit and Integration Tests"
status: pending
priority: P1
effort: "1d"
dependencies: [1, 2, 3, 4]
---

# Phase 5: Unit and Integration Tests

## Overview

Comprehensive test coverage for all challenge engine components. Tests must cover happy paths, edge cases, and security scenarios.

## Requirements

**Unit Tests:**
- Template rendering
- PoW verification
- Difficulty mapping
- Config parsing
- Cookie parsing

**Integration Tests:**
- Full challenge flow (request → challenge → solve → verify → allow)
- Cookie bypass flow
- Binding mismatch rejection
- Concurrent challenges

## Related Code Files

**Create:**
- `crates/waf-engine/tests/challenge_renderer.rs`
- `crates/waf-engine/tests/challenge_pow.rs`
- `crates/waf-engine/tests/challenge_flow.rs`
- `crates/waf-engine/tests/challenge_config.rs`

## Implementation Steps

### Step 1: Template rendering tests

```rust
// crates/waf-engine/tests/challenge_renderer.rs
use waf_engine::challenge::{ChallengeContext, render_challenge_page};

#[test]
fn test_render_challenge_page_basic() {
    let ctx = ChallengeContext {
        token: "test_token_123".into(),
        difficulty: 16,
        redirect_url: "https://example.com/original".into(),
        branding_title: "Security Check".into(),
        branding_message: "Please wait...".into(),
    };
    
    let html = render_challenge_page(&ctx).unwrap();
    
    assert!(html.contains("test_token_123"));
    assert!(html.contains("d=16"));
    assert!(html.contains("https://example.com/original"));
    assert!(html.contains("Security Check"));
    assert!(html.contains("Please wait..."));
}

#[test]
fn test_render_challenge_page_escapes_xss() {
    let ctx = ChallengeContext {
        token: "<script>alert('xss')</script>".into(),
        difficulty: 16,
        redirect_url: "javascript:alert(1)".into(),
        branding_title: "<img onerror='alert(1)'>".into(),
        branding_message: "Test".into(),
    };
    
    let html = render_challenge_page(&ctx).unwrap();
    
    assert!(!html.contains("<script>"));
    assert!(html.contains("&lt;script&gt;"));
    assert!(!html.contains("javascript:"));
}

#[test]
fn test_render_challenge_page_size_limit() {
    let ctx = ChallengeContext {
        token: "x".repeat(100),
        difficulty: 16,
        redirect_url: "https://example.com".into(),
        branding_title: "Test".into(),
        branding_message: "Test".into(),
    };
    
    let html = render_challenge_page(&ctx).unwrap();
    
    assert!(html.len() < 5120, "Page size {} exceeds 5KB limit", html.len());
}

#[test]
fn test_render_challenge_page_has_noscript() {
    let ctx = ChallengeContext {
        token: "test".into(),
        difficulty: 16,
        redirect_url: "/".into(),
        branding_title: "Test".into(),
        branding_message: "Test".into(),
    };
    
    let html = render_challenge_page(&ctx).unwrap();
    
    assert!(html.contains("<noscript>"));
    assert!(html.contains("JavaScript Required"));
}
```

### Step 2: PoW verification tests

```rust
// crates/waf-engine/tests/challenge_pow.rs
use waf_engine::challenge::{verify_pow, PowVerifyResult, DifficultyMap, PowSolution};

#[test]
fn test_verify_pow_valid_solution() {
    // Pre-compute a valid solution for testing
    let token = "test_challenge_token";
    let (nonce, _) = find_valid_nonce(token, 8);
    
    assert_eq!(verify_pow(token, &nonce, 8), PowVerifyResult::Valid);
}

#[test]
fn test_verify_pow_insufficient_difficulty() {
    let token = "test_challenge_token";
    let (nonce, _) = find_valid_nonce(token, 8);
    
    // Require more difficulty than provided
    assert_eq!(verify_pow(token, &nonce, 16), PowVerifyResult::InvalidDifficulty);
}

#[test]
fn test_verify_pow_invalid_nonce_format() {
    assert_eq!(verify_pow("token", "not_a_number", 8), PowVerifyResult::InvalidFormat);
    assert_eq!(verify_pow("token", "-1", 8), PowVerifyResult::InvalidFormat);
}

#[test]
fn test_difficulty_map_tiers() {
    let map = DifficultyMap::default();
    
    assert_eq!(map.difficulty_for_risk(25), 16); // Below range, default
    assert_eq!(map.difficulty_for_risk(30), 14); // Tier 1
    assert_eq!(map.difficulty_for_risk(39), 14); // Tier 1
    assert_eq!(map.difficulty_for_risk(40), 16); // Tier 2
    assert_eq!(map.difficulty_for_risk(55), 18); // Tier 3
    assert_eq!(map.difficulty_for_risk(70), 16); // Above range, default
}

#[test]
fn test_pow_solution_parse_valid() {
    let solution = PowSolution::parse_cookie("abc123.456789").unwrap();
    assert_eq!(solution.token, "abc123");
    assert_eq!(solution.nonce, "456789");
}

#[test]
fn test_pow_solution_parse_invalid() {
    assert!(PowSolution::parse_cookie("no_separator").is_none());
    assert!(PowSolution::parse_cookie("").is_none());
    assert!(PowSolution::parse_cookie(".").is_some()); // Empty parts are technically valid
}

fn find_valid_nonce(token: &str, difficulty: u8) -> (String, u64) {
    use sha2::{Sha256, Digest};
    
    for nonce in 0u64.. {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hasher.update(nonce.to_string().as_bytes());
        let hash = hasher.finalize();
        
        let zeros = hash.iter()
            .take_while(|&&b| b == 0)
            .count() * 8;
        
        if zeros as u8 >= difficulty {
            return (nonce.to_string(), nonce);
        }
        
        if nonce > 10_000_000 {
            panic!("Could not find valid nonce");
        }
    }
    unreachable!()
}
```

### Step 3: Integration flow tests

```rust
// crates/waf-engine/tests/challenge_flow.rs
use waf_engine::challenge::*;
use waf_engine::risk::{ChallengeIssuer, ChallengeVerifier, VerifyOutcome};
use std::sync::Arc;

#[tokio::test]
async fn test_challenge_issue_verify_flow() {
    let secret = Arc::new(HmacSecret::generate());
    let nonce_store = Arc::new(NonceStore::new(1000));
    
    let issuer = ChallengeIssuer::new(Arc::clone(&secret), 300);
    let verifier = ChallengeVerifier::new(Arc::clone(&secret), nonce_store);
    
    let binding = "192.168.1.1|ja3hash|ja4hash";
    let now_ms = chrono::Utc::now().timestamp_millis();
    
    // Issue token
    let token = issuer.issue(binding, now_ms);
    
    // Verify token
    let result = verifier.verify(&token, binding, now_ms).await;
    assert!(matches!(result, VerifyOutcome::Valid { .. }));
}

#[tokio::test]
async fn test_challenge_binding_mismatch() {
    let secret = Arc::new(HmacSecret::generate());
    let nonce_store = Arc::new(NonceStore::new(1000));
    
    let issuer = ChallengeIssuer::new(Arc::clone(&secret), 300);
    let verifier = ChallengeVerifier::new(Arc::clone(&secret), nonce_store);
    
    let binding1 = "192.168.1.1|hash1";
    let binding2 = "192.168.1.2|hash2"; // Different IP
    let now_ms = chrono::Utc::now().timestamp_millis();
    
    let token = issuer.issue(binding1, now_ms);
    
    // Verify with different binding should fail
    let result = verifier.verify(&token, binding2, now_ms).await;
    assert!(matches!(result, VerifyOutcome::Invalid(_)));
}

#[tokio::test]
async fn test_challenge_replay_rejected() {
    let secret = Arc::new(HmacSecret::generate());
    let nonce_store = Arc::new(NonceStore::new(1000));
    
    let issuer = ChallengeIssuer::new(Arc::clone(&secret), 300);
    let verifier = ChallengeVerifier::new(Arc::clone(&secret), Arc::clone(&nonce_store));
    
    let binding = "test_binding";
    let now_ms = chrono::Utc::now().timestamp_millis();
    
    let token = issuer.issue(binding, now_ms);
    
    // First verification succeeds
    let result1 = verifier.verify(&token, binding, now_ms).await;
    assert!(matches!(result1, VerifyOutcome::Valid { .. }));
    
    // Second verification (replay) should fail
    let result2 = verifier.verify(&token, binding, now_ms).await;
    assert!(matches!(result2, VerifyOutcome::Replay));
}

#[tokio::test]
async fn test_challenge_expired() {
    let secret = Arc::new(HmacSecret::generate());
    let nonce_store = Arc::new(NonceStore::new(1000));
    
    let issuer = ChallengeIssuer::new(Arc::clone(&secret), 1); // 1 second TTL
    let verifier = ChallengeVerifier::new(Arc::clone(&secret), nonce_store);
    
    let binding = "test_binding";
    let now_ms = chrono::Utc::now().timestamp_millis();
    
    let token = issuer.issue(binding, now_ms);
    
    // Verify after expiry
    let future_ms = now_ms + 2000; // 2 seconds later
    let result = verifier.verify(&token, binding, future_ms).await;
    assert!(matches!(result, VerifyOutcome::Expired));
}

#[tokio::test]
async fn test_concurrent_challenges() {
    use tokio::task::JoinSet;
    
    let secret = Arc::new(HmacSecret::generate());
    let nonce_store = Arc::new(NonceStore::new(10000));
    
    let issuer = Arc::new(ChallengeIssuer::new(Arc::clone(&secret), 300));
    let verifier = Arc::new(ChallengeVerifier::new(Arc::clone(&secret), nonce_store));
    
    let mut set = JoinSet::new();
    
    for i in 0..1000 {
        let issuer = Arc::clone(&issuer);
        let verifier = Arc::clone(&verifier);
        
        set.spawn(async move {
            let binding = format!("binding_{}", i);
            let now_ms = chrono::Utc::now().timestamp_millis();
            
            let token = issuer.issue(&binding, now_ms);
            let result = verifier.verify(&token, &binding, now_ms).await;
            
            assert!(matches!(result, VerifyOutcome::Valid { .. }), "Failed for binding_{}", i);
        });
    }
    
    while let Some(result) = set.join_next().await {
        result.unwrap();
    }
}
```

### Step 4: Config tests

```rust
// crates/waf-engine/tests/challenge_config.rs
use waf_engine::challenge::{ChallengeConfigLoader, DifficultyMap};
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_config_load_valid() {
    let yaml = r#"
challenge:
  enabled: true
  type: js_challenge
  difficulty:
    default: 16
    tiers:
      - min_risk: 30
        max_risk: 50
        difficulty: 14
  token:
    ttl_secs: 300
    cookie_name: __waf_cc
    cookie_max_age: 300
    same_site: Strict
    http_only: false
  branding:
    title: Test
    message: Testing
  nonce_store:
    capacity: 1000
"#;
    
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(yaml.as_bytes()).unwrap();
    
    let loader = ChallengeConfigLoader::load(file.path()).unwrap();
    let config = loader.config();
    
    assert!(config.enabled);
    assert_eq!(config.r#type, "js_challenge");
    assert_eq!(config.difficulty.default, 16);
    assert_eq!(config.token.ttl_secs, 300);
}

#[test]
fn test_config_defaults() {
    let yaml = r#"
challenge:
  difficulty:
    default: 16
    tiers: []
  token: {}
  branding: {}
  nonce_store: {}
"#;
    
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(yaml.as_bytes()).unwrap();
    
    let loader = ChallengeConfigLoader::load(file.path()).unwrap();
    let config = loader.config();
    
    // Check defaults applied
    assert!(config.enabled);
    assert_eq!(config.token.cookie_name, "__waf_cc");
    assert_eq!(config.branding.title, "Security Check");
}

#[test]
fn test_difficulty_map_from_config() {
    let yaml = r#"
challenge:
  difficulty:
    default: 14
    tiers:
      - min_risk: 50
        max_risk: 70
        difficulty: 18
  token: {}
  branding: {}
  nonce_store: {}
"#;
    
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(yaml.as_bytes()).unwrap();
    
    let loader = ChallengeConfigLoader::load(file.path()).unwrap();
    let config = loader.config();
    let map: DifficultyMap = (&config.difficulty).into();
    
    assert_eq!(map.difficulty_for_risk(40), 14); // default
    assert_eq!(map.difficulty_for_risk(60), 18); // tier
}
```

## Success Criteria

- [ ] All unit tests pass (`cargo test -p waf-engine`)
- [ ] All integration tests pass
- [ ] XSS escape tests verify security
- [ ] Concurrent test completes 1000 challenges without race
- [ ] Replay attack properly rejected
- [ ] Config loading handles defaults correctly
- [ ] Test coverage ≥ 80% for challenge module

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| Flaky concurrent tests | Use deterministic ordering where possible |
| Slow PoW tests | Use low difficulty (8) for unit tests |
| Temp file cleanup | Use tempfile crate with auto-cleanup |
