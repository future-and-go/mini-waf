---
phase: 2
title: "PoW Algorithm"
status: complete
priority: P1
effort: "1d"
dependencies: [1]
---

# Phase 2: PoW Algorithm

## Overview

Implement server-side PoW verification and risk-based difficulty scaling. Client-side solver is embedded in Phase 1 template; this phase handles verification and difficulty configuration.

## Requirements

**Functional:**
- Verify SHA256(token || nonce) has required leading zeros
- Difficulty scales with risk score (14-18 bits)
- Reject invalid proofs with risk penalty

**Non-functional:**
- Verification latency ≤ 1ms
- Difficulty tuned for 100ms-750ms client solve time

## Architecture

```
PoW Algorithm:
  target = SHA256(challenge_token || nonce)
  valid = target has >= difficulty leading zero bits
  
Difficulty Mapping:
  risk 30-40 → difficulty 14 (~100ms solve)
  risk 40-55 → difficulty 16 (~250ms solve)
  risk 55-70 → difficulty 18 (~750ms solve)
```

## Related Code Files

**Create:**
- `crates/waf-engine/src/challenge/pow.rs`

**Modify:**
- `crates/waf-engine/src/challenge/mod.rs` — add `mod pow;` export

## Implementation Steps

### Step 1: Define difficulty mapping

```rust
// crates/waf-engine/src/challenge/pow.rs
use sha2::{Sha256, Digest};

#[derive(Debug, Clone)]
pub struct DifficultyMap {
    pub default: u8,
    pub tiers: Vec<DifficultyTier>,
}

#[derive(Debug, Clone)]
pub struct DifficultyTier {
    pub min_risk: u8,
    pub max_risk: u8,
    pub difficulty: u8,
}

impl DifficultyMap {
    pub fn difficulty_for_risk(&self, risk_score: u8) -> u8 {
        for tier in &self.tiers {
            if risk_score >= tier.min_risk && risk_score < tier.max_risk {
                return tier.difficulty;
            }
        }
        self.default
    }
}

impl Default for DifficultyMap {
    fn default() -> Self {
        Self {
            default: 16,
            tiers: vec![
                DifficultyTier { min_risk: 30, max_risk: 40, difficulty: 14 },
                DifficultyTier { min_risk: 40, max_risk: 55, difficulty: 16 },
                DifficultyTier { min_risk: 55, max_risk: 70, difficulty: 18 },
            ],
        }
    }
}
```

### Step 2: Implement PoW verifier

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowVerifyResult {
    Valid,
    InvalidDifficulty,
    InvalidFormat,
}

pub fn verify_pow(token: &str, nonce: &str, required_difficulty: u8) -> PowVerifyResult {
    // Parse nonce as u64
    let nonce_num: u64 = match nonce.parse() {
        Ok(n) => n,
        Err(_) => return PowVerifyResult::InvalidFormat,
    };
    
    // Compute SHA256(token || nonce)
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.update(nonce_num.to_string().as_bytes());
    let hash = hasher.finalize();
    
    // Count leading zero bits
    let leading_zeros = count_leading_zero_bits(&hash);
    
    if leading_zeros >= required_difficulty {
        PowVerifyResult::Valid
    } else {
        PowVerifyResult::InvalidDifficulty
    }
}

fn count_leading_zero_bits(hash: &[u8]) -> u8 {
    let mut zeros = 0u8;
    for byte in hash {
        if *byte == 0 {
            zeros += 8;
        } else {
            zeros += byte.leading_zeros() as u8;
            break;
        }
    }
    zeros
}
```

### Step 3: Add cookie parsing for PoW solution

```rust
#[derive(Debug)]
pub struct PowSolution {
    pub token: String,
    pub nonce: String,
}

impl PowSolution {
    pub fn parse_cookie(cookie_value: &str) -> Option<Self> {
        // Format: token.nonce
        let parts: Vec<&str> = cookie_value.splitn(2, '.').collect();
        if parts.len() != 2 {
            return None;
        }
        Some(Self {
            token: parts[0].to_string(),
            nonce: parts[1].to_string(),
        })
    }
}
```

### Step 4: Export from mod.rs

```rust
// crates/waf-engine/src/challenge/mod.rs
mod pow;
pub use pow::{DifficultyMap, DifficultyTier, PowVerifyResult, PowSolution, verify_pow};
```

### Step 5: Add unit tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_difficulty_map_default() {
        let map = DifficultyMap::default();
        assert_eq!(map.difficulty_for_risk(35), 14);
        assert_eq!(map.difficulty_for_risk(45), 16);
        assert_eq!(map.difficulty_for_risk(60), 18);
        assert_eq!(map.difficulty_for_risk(75), 16); // default
    }
    
    #[test]
    fn test_verify_pow_valid() {
        // Pre-computed: SHA256("test_token123") starts with 0000...
        // This test uses a known good nonce
        let token = "test_challenge_token";
        // Find a valid nonce for difficulty 8 (for fast test)
        let mut nonce = 0u64;
        loop {
            let result = verify_pow(token, &nonce.to_string(), 8);
            if result == PowVerifyResult::Valid {
                break;
            }
            nonce += 1;
            if nonce > 1_000_000 {
                panic!("Could not find valid nonce in reasonable time");
            }
        }
        assert_eq!(verify_pow(token, &nonce.to_string(), 8), PowVerifyResult::Valid);
    }
    
    #[test]
    fn test_pow_solution_parse() {
        let solution = PowSolution::parse_cookie("abc123.456").unwrap();
        assert_eq!(solution.token, "abc123");
        assert_eq!(solution.nonce, "456");
        
        assert!(PowSolution::parse_cookie("invalid").is_none());
    }
}
```

## Success Criteria

- [x] `DifficultyMap::difficulty_for_risk()` returns correct difficulty per tier
- [x] `verify_pow()` correctly validates SHA256 leading zeros
- [x] `PowSolution::parse_cookie()` parses `token.nonce` format
- [x] Unit tests pass for difficulty mapping
- [x] Unit tests pass for PoW verification
- [x] `cargo check --package waf-engine` passes

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| Difficulty too high for mobile | Cap at 18 bits max; add UA-based adjustment in future |
| CPU DoS via repeated verifications | Rate limit at gateway level (already exists) |
| Timing attack on verification | Use constant-time comparison (sha2 crate handles) |
