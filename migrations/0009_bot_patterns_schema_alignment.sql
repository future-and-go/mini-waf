-- Phase 3: Align bot_patterns schema with YAML bot-detection rules and Rust RuleAction enum.
--
-- Fixes three mismatches between the 0007 DDL and actual usage:
--   1. pattern VARCHAR(500) truncates long regex patterns → widen to TEXT
--   2. pattern_type only documented ua|ip|behavior → add user_agent|headers|body|path
--   3. action only documented block|log|captcha|allow → align with RuleAction enum (block|log|challenge|allow)
--
-- Safe on existing data: VARCHAR→TEXT is metadata-only in PostgreSQL (no rewrite).
-- No CHECK constraints exist on the original table, so no DROP/ADD needed.

-- 1) Widen pattern column to accept arbitrarily long regex strings.
ALTER TABLE bot_patterns ALTER COLUMN pattern TYPE TEXT;

-- 2) Document expanded pattern_type vocabulary (no CHECK exists to update).
COMMENT ON COLUMN bot_patterns.pattern_type IS
  'Pattern target field: user_agent, headers, body, path (legacy: ua, ip, behavior)';

-- 3) Document expanded action vocabulary including challenge.
--    captcha intentionally omitted: RuleAction enum has no Captcha variant;
--    parse_str silently maps unknown values to Block.
COMMENT ON COLUMN bot_patterns.action IS
  'Action on match: block, log, challenge, allow';
