---
phase: 5
title: "challenge module"
status: pending
effort: "0.5d"
priority: P1
dependencies: [3]
---

# Phase 5: challenge module

## Overview

Medium-small schema: `challenge:` root with `[challenge.difficulty]` (scalar `default` + a sequence `tiers:` of records), `[challenge.token]`, `[challenge.branding]`, `[challenge.nonce_store]`. Sequence is array-of-tables `[[challenge.difficulty.tiers]]`. Pattern is identical to Phase 3 — no new mechanisms.

## Requirements

- Functional: `ChallengeConfig::from_path` reads TOML; same struct shape.
- Functional: `[[challenge.difficulty.tiers]]` deserialises to current `Vec<DifficultyTier>`.
- Functional: `configs/challenge.toml` ships, hand-translated with comments.
- Functional: `challenge_api.rs` switches to TOML codec.

## Related Code Files

- Modify: `crates/waf-engine/src/challenge/config.rs` (parser, doc, tests)
- Modify: `crates/waf-engine/src/challenge/reload.rs` (test fixtures, path)
- Modify: `crates/waf-api/src/challenge_api.rs` (codec, path, error string `"parse YAML"` → `"parse TOML"`)
- Modify: `crates/waf-engine/tests/challenge_config.rs` (fixture rewrite)
- Create: `configs/challenge.toml`
- Delete: `configs/challenge.yaml`

## Implementation Steps

1. **TDD red:** rewrite all inline YAML test literals in `challenge/config.rs::tests`, `challenge/reload.rs::tests`, and the standalone `tests/challenge_config.rs` into TOML. Three tier records become:
   ```toml
   [[challenge.difficulty.tiers]]
   min_risk = 30
   max_risk = 40
   difficulty = 14
   ```
2. Add equivalence test using Phase 1 helper.
3. Confirm red.
4. Hand-write `configs/challenge.toml`: `[challenge]` scalars first, then `[challenge.difficulty]` (with its inline `default = 16` BEFORE the `[[…tiers]]` arrays), then `[challenge.token]`, etc.
5. Swap parser: `toml::from_str(s).context("challenge: parse TOML")?` (note: the current `ChallengeConfig::from_path` may not have a `from_yaml_str` analogue — confirm and rename to `from_toml_str` if so).
6. Update `challenge_api.rs`: `configs/challenge.yaml` → `.toml`, codec helpers, comment header, error strings (`"parse YAML"` → `"parse TOML"`).
7. Update `engine.rs` doc references for `challenge.yaml`.
8. Delete `configs/challenge.yaml`.
9. Tests:
   ```bash
   cargo test -p waf-engine challenge::
   cargo test -p waf-engine --test challenge_config
   cargo test -p waf-api challenge
   ```

## Todo List

- [ ] Unit + integration tests rewritten (red)
- [ ] Equivalence test added
- [ ] `configs/challenge.toml` hand-written
- [ ] Parser swapped
- [ ] `challenge_api.rs` codec + path + error strings
- [ ] `configs/challenge.yaml` deleted
- [ ] All challenge tests green
- [ ] Clippy clean

## Success Criteria

- [ ] `cargo test -p waf-engine challenge::` green
- [ ] `tests/challenge_config.rs` green
- [ ] Admin endpoints unchanged in API shape

## Risk Assessment

- **Risk:** `same_site: Strict` (YAML string) — TOML must quote: `same_site = "Strict"`. Easy typo. **Mitigation:** Equivalence test catches.
- **Risk:** `http_only: false` is a bool — straightforward. No risk.
