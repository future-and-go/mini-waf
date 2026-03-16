-- Phase 7: Rule management tables

-- Configured rule sources (mirrors the [rules.sources] TOML config but DB-managed)
CREATE TABLE IF NOT EXISTS rule_sources (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(100) UNIQUE NOT NULL,
    source_type     VARCHAR(20) NOT NULL,   -- local_file | local_dir | remote_url | builtin
    url             VARCHAR(1000),
    path            VARCHAR(500),
    format          VARCHAR(20) NOT NULL DEFAULT 'yaml',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    last_updated    TIMESTAMPTZ,
    last_hash       VARCHAR(64),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rule_sources_name ON rule_sources(name);

-- Per-rule overrides (enable/disable a specific rule for a specific host)
CREATE TABLE IF NOT EXISTS rule_overrides (
    id              SERIAL PRIMARY KEY,
    rule_id         VARCHAR(100) NOT NULL,
    host_id         UUID REFERENCES hosts(id) ON DELETE CASCADE,
    enabled         BOOLEAN,                    -- null = inherit default
    action_override VARCHAR(20),                -- null = inherit default
    note            TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (rule_id, host_id)
);

CREATE INDEX IF NOT EXISTS idx_rule_overrides_rule ON rule_overrides(rule_id);
CREATE INDEX IF NOT EXISTS idx_rule_overrides_host ON rule_overrides(host_id);

-- Bot pattern management (extends the built-in bot check)
CREATE TABLE IF NOT EXISTS bot_patterns (
    id          SERIAL PRIMARY KEY,
    pattern     VARCHAR(500) NOT NULL,
    pattern_type VARCHAR(20) NOT NULL DEFAULT 'ua',  -- ua | ip | behavior
    action      VARCHAR(20) NOT NULL DEFAULT 'block', -- block | log | captcha | allow
    description TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_bot_patterns_enabled ON bot_patterns(enabled);
