-- Migration 0010: Add name and tags columns to bot_patterns table.
--
-- The bot_patterns table (created in 0007) only had pattern/action/description.
-- The admin UI needs name (human-readable label) and tags (array for filtering
-- by category: good-bot, ai-crawler, seo-tool, scraper, etc.).
--
-- Safe on existing data: column additions with defaults are metadata-only.

ALTER TABLE bot_patterns ADD COLUMN IF NOT EXISTS name VARCHAR(200) NOT NULL DEFAULT '';
ALTER TABLE bot_patterns ADD COLUMN IF NOT EXISTS tags TEXT[] NOT NULL DEFAULT '{}';
