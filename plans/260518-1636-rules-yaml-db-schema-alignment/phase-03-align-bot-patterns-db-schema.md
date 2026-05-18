---
phase: 3
title: "Align bot_patterns DB Schema"
status: done
priority: P1
effort: "2h"
dependencies: []
---

# Phase 3: Align bot_patterns DB Schema

## Overview

The `bot_patterns` table in `0007_rule_management.sql` has three mismatches with the YAML bot-detection rules that prevent clean import:

1. **`pattern` VARCHAR(500)** — some bot-detection regex patterns exceed 500 characters (e.g., `BOT-CRAWL-009` generic bad bot UA pattern, `BOT-CRED-008` disposable email pattern). INSERT fails with truncation.
2. **`pattern_type` enum mismatch** — DB expects `ua | ip | behavior`, YAML uses `user_agent | headers | body | path`. No mapping layer exists.
3. **`action` constraint mismatch** — Rust `RuleAction` enum has `Challenge` variant, but DB CHECK constraint only allows `block | log | captcha | allow`. Future bot rules using `challenge` would violate the constraint.

**Why a migration:** These are DDL changes — column type widening and CHECK constraint updates. A new migration file is the correct, reversible approach. Modifying the original `0007` file would break existing deployments that already ran it.

**Alternative considered:** Adding a Rust mapping layer that converts `user_agent → ua` on INSERT. Rejected — it hides the impedance mismatch and would need maintaining. Better to align the DB with the actual domain vocabulary used everywhere else (YAML files, Rust enums, API).

## Requirements

- Functional: Bot-detection rules with patterns >500 chars can be stored in `bot_patterns`
- Functional: All YAML `pattern_field` values can be stored in `pattern_type` without mapping
- Functional: `challenge` action from Rust `RuleAction` enum can be stored in DB
- Non-functional: Migration must be backward-compatible (no data loss for existing rows)

## Architecture

```
Current schema:                      Target schema:
┌─────────────────────────┐          ┌─────────────────────────┐
│ pattern VARCHAR(500)    │    →     │ pattern TEXT             │
│ pattern_type VARCHAR(20)│    →     │ pattern_type VARCHAR(20) │
│   (ua|ip|behavior)      │          │   (+ user_agent|headers| │
│                         │          │     body|path)           │
│ action VARCHAR(20)      │    →     │ action VARCHAR(20)       │
│   (block|log|captcha|   │          │   (+ challenge)          │
│    allow)               │          │                          │
└─────────────────────────┘          └─────────────────────────┘
```

## Related Code Files

- Create: `migrations/0009_bot_patterns_schema_alignment.sql` — new migration
- Read: `migrations/0007_rule_management.sql` — original schema
- Read: `rules/bot-detection/crawlers.yaml` — verify pattern lengths
- Read: `rules/bot-detection/credential-stuffing.yaml` — verify pattern lengths
- Modify: `crates/waf-storage/src/models.rs` — update `BotPattern` struct if it has constrained types (check first)
- Read: `crates/waf-api/src/` — check if API validates `pattern_type` values

## Implementation Steps

1. **Measure actual max pattern lengths** to confirm the issue:
   ```bash
   grep "^pattern:" rules/bot-detection/*.yaml | awk '{print length, $0}' | sort -rn | head -5
   ```

2. **Create migration file `migrations/0009_bot_patterns_schema_alignment.sql`:**

   ```sql
   -- Widen pattern column: some bot-detection regex patterns exceed 500 chars
   ALTER TABLE bot_patterns ALTER COLUMN pattern TYPE TEXT;

   -- Expand pattern_type to accept YAML field names directly
   -- Previous: only ua|ip|behavior
   -- Now: also user_agent|headers|body|path (matching YAML pattern_field values)
   COMMENT ON COLUMN bot_patterns.pattern_type IS
     'Pattern target: ua, ip, behavior, user_agent, headers, body, path';

   -- Add challenge to action constraint (matches Rust RuleAction::Challenge)
   -- No CHECK constraint existed in original DDL (it was VARCHAR(20) with a comment)
   -- Update the column comment to document valid values
   COMMENT ON COLUMN bot_patterns.action IS
     'Action on match: block, log, captcha, challenge, allow';
   ```

   **Important:** Check whether the original migration used an actual `CHECK` constraint or just a comment. If it's only a comment (likely — the DDL shows no CHECK), then only the COMMENT update is needed. If there IS a CHECK constraint, it must be dropped and recreated.

3. **Verify no CHECK constraint exists** on the original table:
   ```bash
   psql -c "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid = 'bot_patterns'::regclass AND contype = 'c';"
   ```

4. **If CHECK constraint exists**, add to migration:
   ```sql
   ALTER TABLE bot_patterns DROP CONSTRAINT IF EXISTS bot_patterns_action_check;
   ALTER TABLE bot_patterns ADD CONSTRAINT bot_patterns_action_check
     CHECK (action IN ('block', 'log', 'captcha', 'challenge', 'allow'));
   ```

5. **Update `BotPattern` Rust struct** (if it exists in `waf-storage/src/models.rs`):
   - Change `pattern: String` field max validation (if any) to allow unbounded
   - Verify `pattern_type` field accepts the expanded set of values

6. **Update API validation** (if `waf-api` validates `pattern_type`):
   - Add `user_agent`, `headers`, `body`, `path` to any allowlist
   - Add `challenge` to action allowlist

7. **Run migration locally and verify:**
   ```bash
   psql -f migrations/0009_bot_patterns_schema_alignment.sql
   ```

8. **Run `cargo check`** to verify Rust code compiles with updated models

## Success Criteria

- [x] Migration file `0009_bot_patterns_schema_alignment.sql` created
- [x] `pattern` column widened to `TEXT`
- [x] `pattern_type` accepts `user_agent`, `headers`, `body`, `path` in addition to `ua`, `ip`, `behavior`
- [x] `action` accepts `challenge` in addition to `block`, `log`, `captcha`, `allow`
- [x] Migration runs successfully against existing database (no data loss)
- [x] No Rust model/API validation needed (BotPattern struct does not exist in models.rs; no API validation layer for bot_patterns)
- [x] `cargo check` passes

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| `ALTER COLUMN TYPE TEXT` locks table on large datasets | Low (bot_patterns likely small) | Low | Table is typically <1000 rows; ALTER completes instantly |
| Existing rows have `pattern_type: ua` — do we also migrate data? | Low | Low | Keep existing `ua`/`ip`/`behavior` values valid. New inserts can use either vocabulary. No data migration needed. |
| Other services depend on the CHECK constraint | Low | Medium | Check for dependent triggers or application code before removing constraint |

## Common Pitfalls

- **Don't modify `0007_rule_management.sql` directly.** Existing deployments already ran that migration. Changes to it will be silently ignored by the migration runner. Always create a NEW migration file with the next sequence number.
- **Don't assume there's a CHECK constraint.** The original DDL uses comments (`-- block | log | captcha | allow`) not an actual SQL CHECK. Verify with `pg_constraint` query before writing ALTER DROP CONSTRAINT statements.
- **VARCHAR → TEXT is safe in PostgreSQL.** Unlike some databases, PostgreSQL stores VARCHAR and TEXT identically. Widening from VARCHAR(500) to TEXT requires no data rewrite — it's a metadata-only change, instant even on large tables.

## Implementation Notes

**Completed:** Migration `migrations/0009_bot_patterns_schema_alignment.sql` created with:
1. Widened `pattern` VARCHAR(500) → TEXT
2. Documented expanded `pattern_type` vocabulary (added `user_agent`, `headers`, `body`, `path` alongside `ua`, `ip`, `behavior`)
3. Documented expanded `action` vocabulary (added `challenge` alongside `block`, `log`, `captcha`, `allow`)

**Rust Model/API Assessment:** No changes required. Investigation confirmed:
- No `BotPattern` struct exists in `crates/waf-storage/src/models.rs`
- No API validation layer exists for `bot_patterns` table
- Migration handles schema alignment; application code consumes schema as-is via dynamic SQL or ORM
