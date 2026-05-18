# Phase 3: Bot Patterns DB Schema Alignment

**Date**: 2026-05-18 14:45
**Severity**: Medium
**Component**: Database schema, bot_patterns table
**Status**: Resolved

## What Happened

Aligned `bot_patterns` PostgreSQL schema with YAML bot-detection rules and Rust `RuleAction` enum. Created migration `migrations/0009_bot_patterns_schema_alignment.sql` that expanded `pattern` column from VARCHAR(500) to TEXT and documented expanded `pattern_type` and `action` vocabularies.

## The Brutal Truth

This was supposed to be a simple schema alignment pass. Instead, code review caught a **semantic trap** we nearly shipped: the original DDL (0007) and our migration both listed `captcha` as a valid action value, but the `RuleAction` enum has no `Captcha` variant. Any operator expecting CAPTCHA behavior would get silently mapped to `Block` by `parse_str`. This would've caused real incidents in production.

## Technical Details

**Schema changes:**
- Widened `pattern` from VARCHAR(500) to TEXT (metadata-only change in PostgreSQL, zero-cost)
- Documented `pattern_type` vocabulary: `user_agent, headers, body, path` with legacy notation for `ua, ip, behavior`
- Documented `action` vocabulary: `block, log, challenge, allow` (removed `captcha`)

**The catch:** `RuleAction` enum variants are `Block`, `Log`, `Challenge`, `Allow`. The original DDL included `captcha` in the COMMENT, creating a mismatch between documented schema and actual Rust behavior.

## What We Tried

1. Attempted to add `Captcha` variant to `RuleAction` — rejected as out-of-scope for schema alignment
2. Considered adding CHECK constraints on `action` column — decided against it (original DDL had none; separate concern)
3. Verified all 1288 tests pass and `cargo check` is clean

## Root Cause Analysis

The original 0007 migration was written without consulting the actual `RuleAction` enum definition in `waf-storage`. Schema and code diverged during earlier consolidation phases. No API validation existed for `bot_patterns.action`, so the mismatch went undetected until code review.

## Lessons Learned

1. **Schema comments must reflect code reality.** When documenting enum-like columns, cross-check against the actual enum in code. `parse_str` silent fallback behavior is dangerous — it hides bugs.
2. **Scope discipline saves incidents.** This was a schema alignment task, not a feature task. Removing `captcha` from the comment was the right call. Adding a new `Captcha` variant belongs in a separate feature PR with its own tests.
3. **Backward compatibility notation helps.** Marking old pattern_type values (`ua, ip, behavior`) as "legacy" preserves migration history without forcing deprecation immediately.

## Next Steps

1. ✅ Deploy migration 0009 with corrected `action` values (no `captcha`)
2. ⚠️ **TODO**: Create a separate feature task to implement `Captcha` variant if operators need it (link to roadmap)
3. ✅ Document this schema-code divergence in `./docs/system-architecture.md` (done via commit 2)
4. Consider adding a linting script to catch schema/enum mismatches in CI (future improvement)

**Commits:**
- `feat(db): align bot_patterns schema with rules YAML v1 consolidation`
- `docs: update data-storage-architecture for bot_patterns alignment`
