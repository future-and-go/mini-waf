//! Proof-of-Work verification for challenge responses.
//!
//! Verifies SHA256(token || nonce) has required leading zero bits.
//! Difficulty scales with risk score (14-18 bits).

use sha2::{Digest, Sha256};

/// Maps risk scores to Proof-of-Work difficulty levels.
#[derive(Debug, Clone)]
pub struct DifficultyMap {
    pub default: u8,
    pub tiers: Vec<DifficultyTier>,
}

/// A single tier mapping risk range to difficulty.
#[derive(Debug, Clone)]
pub struct DifficultyTier {
    pub min_risk: u8,
    pub max_risk: u8,
    pub difficulty: u8,
}

impl DifficultyMap {
    /// Returns the difficulty for a given risk score.
    /// Falls back to default if no tier matches.
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
                DifficultyTier {
                    min_risk: 30,
                    max_risk: 40,
                    difficulty: 14,
                },
                DifficultyTier {
                    min_risk: 40,
                    max_risk: 55,
                    difficulty: 16,
                },
                DifficultyTier {
                    min_risk: 55,
                    max_risk: 70,
                    difficulty: 18,
                },
            ],
        }
    }
}

/// Result of Proof-of-Work verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowVerifyResult {
    /// Proof is valid - hash has required leading zeros.
    Valid,
    /// Proof is invalid - insufficient leading zeros.
    InvalidDifficulty,
    /// Nonce format is invalid (not a valid u64).
    InvalidFormat,
}

/// Verifies a Proof-of-Work solution.
///
/// Computes SHA256(token || nonce) and checks for required leading zero bits.
/// Nonce is canonicalized: parsed as u64 then stringified (e.g., "00123" → "123").
/// Client solver must use the same canonicalization.
pub fn verify_pow(token: &str, nonce: &str, required_difficulty: u8) -> PowVerifyResult {
    // Reject oversized nonce strings early to prevent parsing DoS
    if nonce.len() > 20 {
        return PowVerifyResult::InvalidFormat;
    }

    let nonce_num: u64 = match nonce.parse() {
        Ok(n) => n,
        Err(_) => return PowVerifyResult::InvalidFormat,
    };

    // Canonicalize nonce to match client-side: JavaScript's nonce.toString()
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.update(nonce_num.to_string().as_bytes());
    let hash = hasher.finalize();

    let leading_zeros = count_leading_zero_bits(&hash);

    if leading_zeros >= required_difficulty {
        PowVerifyResult::Valid
    } else {
        PowVerifyResult::InvalidDifficulty
    }
}

/// Counts leading zero bits in a hash.
fn count_leading_zero_bits(hash: &[u8]) -> u8 {
    let mut zeros = 0u8;
    for byte in hash {
        if *byte == 0 {
            zeros += 8;
        } else {
            // Safe: leading_zeros on u8 returns 0-8, fits in u8
            #[allow(clippy::cast_possible_truncation)]
            let lz = byte.leading_zeros() as u8;
            zeros += lz;
            break;
        }
    }
    zeros
}

/// Parsed Proof-of-Work solution from cookie.
#[derive(Debug)]
pub struct PowSolution {
    pub token: String,
    pub nonce: String,
}

impl PowSolution {
    /// Parses a cookie value in "token.nonce" format.
    pub fn parse_cookie(cookie_value: &str) -> Option<Self> {
        let (token, nonce) = cookie_value.split_once('.')?;
        if token.is_empty() || nonce.is_empty() {
            return None;
        }
        Some(Self {
            token: token.to_string(),
            nonce: nonce.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_difficulty_map_tier_14() {
        let map = DifficultyMap::default();
        assert_eq!(map.difficulty_for_risk(35), 14);
    }

    #[test]
    fn test_difficulty_map_tier_16() {
        let map = DifficultyMap::default();
        assert_eq!(map.difficulty_for_risk(45), 16);
    }

    #[test]
    fn test_difficulty_map_tier_18() {
        let map = DifficultyMap::default();
        assert_eq!(map.difficulty_for_risk(60), 18);
    }

    #[test]
    fn test_difficulty_map_default_fallback() {
        let map = DifficultyMap::default();
        // Outside all tiers, falls back to default (16)
        assert_eq!(map.difficulty_for_risk(75), 16);
        assert_eq!(map.difficulty_for_risk(25), 16);
    }

    #[test]
    fn test_verify_pow_valid() {
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
    fn test_verify_pow_invalid_difficulty() {
        // Nonce 0 is very unlikely to satisfy difficulty 20
        let result = verify_pow("random_token", "0", 20);
        assert_eq!(result, PowVerifyResult::InvalidDifficulty);
    }

    #[test]
    fn test_verify_pow_invalid_format() {
        let result = verify_pow("token", "not_a_number", 8);
        assert_eq!(result, PowVerifyResult::InvalidFormat);
    }

    #[test]
    fn test_verify_pow_oversized_nonce_rejected() {
        // Oversized nonce string (>20 chars) should be rejected early
        let long_nonce = "1".repeat(21);
        let result = verify_pow("token", &long_nonce, 8);
        assert_eq!(result, PowVerifyResult::InvalidFormat);
    }

    #[test]
    fn test_pow_solution_parse_valid() {
        let solution = PowSolution::parse_cookie("abc123.456").unwrap();
        assert_eq!(solution.token, "abc123");
        assert_eq!(solution.nonce, "456");
    }

    #[test]
    fn test_pow_solution_parse_no_separator() {
        assert!(PowSolution::parse_cookie("invalid").is_none());
    }

    #[test]
    fn test_pow_solution_parse_empty_parts() {
        assert!(PowSolution::parse_cookie(".456").is_none());
        assert!(PowSolution::parse_cookie("abc.").is_none());
        assert!(PowSolution::parse_cookie(".").is_none());
    }

    #[test]
    fn test_count_leading_zero_bits() {
        // All zeros in first byte = 8 zeros
        assert_eq!(count_leading_zero_bits(&[0x00, 0xFF]), 8);
        // 0x0F = 0000 1111, so 4 leading zeros
        assert_eq!(count_leading_zero_bits(&[0x0F, 0xFF]), 4);
        // 0x80 = 1000 0000, so 0 leading zeros
        assert_eq!(count_leading_zero_bits(&[0x80, 0x00]), 0);
        // Two zero bytes then 0x01 = 16 + 7 = 23 leading zeros
        assert_eq!(count_leading_zero_bits(&[0x00, 0x00, 0x01]), 23);
    }
}
