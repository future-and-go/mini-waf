//! FR-006 — Proof-of-Work verification integration tests.
//!
//! Tests PoW verification, difficulty mapping, and cookie parsing.
//! Focuses on edge cases and integration scenarios.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::missing_docs_in_private_items
)]

use sha2::{Digest, Sha256};
use waf_engine::challenge::{DifficultyMap, DifficultyTier, PowSolution, PowVerifyResult, verify_pow};

fn find_valid_nonce(token: &str, difficulty: u8) -> u64 {
    for nonce in 0u64.. {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hasher.update(nonce.to_string().as_bytes());
        let hash = hasher.finalize();

        let leading_zeros = count_leading_zero_bits(&hash);
        if leading_zeros >= difficulty {
            return nonce;
        }
        if nonce > 5_000_000 {
            panic!("Could not find valid nonce for difficulty {difficulty}");
        }
    }
    unreachable!()
}

fn count_leading_zero_bits(hash: &[u8]) -> u8 {
    let mut zeros = 0u8;
    for byte in hash {
        if *byte == 0 {
            zeros += 8;
        } else {
            #[allow(clippy::cast_possible_truncation)]
            let lz = byte.leading_zeros() as u8;
            zeros += lz;
            break;
        }
    }
    zeros
}

#[test]
fn verify_pow_accepts_valid_solution() {
    let token = "test_challenge_token_001";
    let nonce = find_valid_nonce(token, 8);

    let result = verify_pow(token, &nonce.to_string(), 8);
    assert_eq!(result, PowVerifyResult::Valid);
}

#[test]
fn verify_pow_rejects_insufficient_difficulty() {
    let token = "difficulty_test_token";
    let nonce = find_valid_nonce(token, 8);

    let result = verify_pow(token, &nonce.to_string(), 16);
    assert_eq!(result, PowVerifyResult::InvalidDifficulty);
}

#[test]
fn verify_pow_accepts_higher_difficulty_than_required() {
    let token = "over_difficulty_token";
    let nonce = find_valid_nonce(token, 12);

    let result = verify_pow(token, &nonce.to_string(), 8);
    assert_eq!(
        result,
        PowVerifyResult::Valid,
        "higher difficulty should satisfy lower requirement"
    );
}

#[test]
fn verify_pow_rejects_invalid_nonce_formats() {
    let invalid_nonces = [
        ("not_a_number", "non-numeric"),
        ("-1", "negative number"),
        ("12.34", "decimal number"),
        ("1e10", "scientific notation"),
        ("0x1234", "hex format"),
        ("", "empty string"),
    ];

    for (nonce, desc) in invalid_nonces {
        let result = verify_pow("token", nonce, 8);
        assert_eq!(
            result,
            PowVerifyResult::InvalidFormat,
            "{desc} should be invalid format"
        );
    }
}

#[test]
fn verify_pow_rejects_oversized_nonce() {
    let long_nonce = "1".repeat(21);
    let result = verify_pow("token", &long_nonce, 8);
    assert_eq!(
        result,
        PowVerifyResult::InvalidFormat,
        "nonce >20 chars should be rejected"
    );

    let max_valid = "1".repeat(20);
    let result = verify_pow("token", &max_valid, 8);
    assert_ne!(result, PowVerifyResult::InvalidFormat, "20-char nonce should be parsed");
}

#[test]
fn verify_pow_canonicalizes_nonce() {
    let token = "canonicalize_test";
    let nonce = find_valid_nonce(token, 8);
    let padded = format!("{:0>10}", nonce);
    let result = verify_pow(token, &padded, 8);
    assert_eq!(
        result,
        PowVerifyResult::Valid,
        "padded nonce should match canonical form"
    );
}

#[test]
fn difficulty_map_default_tiers() {
    let map = DifficultyMap::default();

    assert_eq!(map.default, 16, "default should be 16");
    assert_eq!(map.tiers.len(), 3, "should have 3 default tiers");

    assert_eq!(map.difficulty_for_risk(25), 16, "below all tiers -> default");
    assert_eq!(map.difficulty_for_risk(35), 14, "30-40 -> tier 1");
    assert_eq!(map.difficulty_for_risk(45), 16, "40-55 -> tier 2");
    assert_eq!(map.difficulty_for_risk(60), 18, "55-70 -> tier 3");
    assert_eq!(map.difficulty_for_risk(80), 16, "above all tiers -> default");
}

#[test]
fn difficulty_map_boundary_values() {
    let map = DifficultyMap::default();

    assert_eq!(map.difficulty_for_risk(29), 16, "risk 29 -> default (below tier 1)");
    assert_eq!(map.difficulty_for_risk(30), 14, "risk 30 -> tier 1 (inclusive)");
    assert_eq!(map.difficulty_for_risk(39), 14, "risk 39 -> tier 1");
    assert_eq!(map.difficulty_for_risk(40), 16, "risk 40 -> tier 2 (exclusive upper)");
    assert_eq!(map.difficulty_for_risk(54), 16, "risk 54 -> tier 2");
    assert_eq!(map.difficulty_for_risk(55), 18, "risk 55 -> tier 3");
    assert_eq!(map.difficulty_for_risk(69), 18, "risk 69 -> tier 3");
    assert_eq!(map.difficulty_for_risk(70), 16, "risk 70 -> default (above tier 3)");
}

#[test]
fn difficulty_map_custom_tiers() {
    let map = DifficultyMap {
        default: 12,
        tiers: vec![
            DifficultyTier {
                min_risk: 0,
                max_risk: 20,
                difficulty: 8,
            },
            DifficultyTier {
                min_risk: 80,
                max_risk: 100,
                difficulty: 20,
            },
        ],
    };

    assert_eq!(map.difficulty_for_risk(10), 8, "low risk -> easy");
    assert_eq!(map.difficulty_for_risk(50), 12, "mid risk -> default");
    assert_eq!(map.difficulty_for_risk(90), 20, "high risk -> hard");
}

#[test]
fn difficulty_map_empty_tiers() {
    let map = DifficultyMap {
        default: 10,
        tiers: vec![],
    };

    for risk in [0, 25, 50, 75, 100] {
        assert_eq!(map.difficulty_for_risk(risk), 10, "all risks should use default");
    }
}

#[test]
fn pow_solution_parses_valid_cookie() {
    let solution = PowSolution::parse_cookie("token123.456789").unwrap();
    assert_eq!(solution.token, "token123");
    assert_eq!(solution.nonce, "456789");
}

#[test]
fn pow_solution_parses_complex_token() {
    let solution = PowSolution::parse_cookie("abc-def_123.99999").unwrap();
    assert_eq!(solution.token, "abc-def_123");
    assert_eq!(solution.nonce, "99999");
}

#[test]
fn pow_solution_handles_multiple_dots() {
    let solution = PowSolution::parse_cookie("token.with.dots.12345").unwrap();
    assert_eq!(solution.token, "token");
    assert_eq!(solution.nonce, "with.dots.12345");
}

#[test]
fn pow_solution_rejects_missing_separator() {
    assert!(PowSolution::parse_cookie("no_separator").is_none());
}

#[test]
fn pow_solution_rejects_empty_parts() {
    assert!(PowSolution::parse_cookie(".456").is_none(), "empty token");
    assert!(PowSolution::parse_cookie("abc.").is_none(), "empty nonce");
    assert!(PowSolution::parse_cookie(".").is_none(), "both empty");
}

#[test]
fn pow_solution_rejects_empty_string() {
    assert!(PowSolution::parse_cookie("").is_none());
}

#[test]
fn verify_pow_with_real_computed_solution() {
    let token = "real_integration_test_token";
    let difficulty: u8 = 10;

    let nonce = find_valid_nonce(token, difficulty);

    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.update(nonce.to_string().as_bytes());
    let hash = hasher.finalize();
    let zeros = count_leading_zero_bits(&hash);

    assert!(zeros >= difficulty, "computed nonce should have sufficient zeros");
    assert_eq!(
        verify_pow(token, &nonce.to_string(), difficulty),
        PowVerifyResult::Valid
    );
}

#[test]
fn verify_pow_with_zero_nonce() {
    let result = verify_pow("some_token", "0", 20);
    assert!(matches!(
        result,
        PowVerifyResult::Valid | PowVerifyResult::InvalidDifficulty
    ));
}

#[test]
fn verify_pow_with_max_u64_nonce() {
    let max_nonce = u64::MAX.to_string();
    let result = verify_pow("token", &max_nonce, 8);
    assert!(matches!(
        result,
        PowVerifyResult::Valid | PowVerifyResult::InvalidDifficulty
    ));
}

#[test]
fn difficulty_map_extreme_risks() {
    let map = DifficultyMap::default();

    assert_eq!(map.difficulty_for_risk(0), 16, "risk 0 -> default");
    assert_eq!(map.difficulty_for_risk(100), 16, "risk 100 -> default");
    assert_eq!(map.difficulty_for_risk(255), 16, "risk 255 -> default");
}
