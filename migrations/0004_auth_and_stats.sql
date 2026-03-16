-- Phase 4: Auth, Statistics, Notifications

-- Admin users table
CREATE TABLE IF NOT EXISTS admin_users (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username    VARCHAR(64) NOT NULL UNIQUE,
    email       VARCHAR(256),
    password_hash TEXT NOT NULL,
    role        VARCHAR(32) NOT NULL DEFAULT 'admin',
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    totp_secret TEXT,
    totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    last_login  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Refresh tokens for JWT auth
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id    ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);

-- Request statistics (hourly/daily aggregated)
CREATE TABLE IF NOT EXISTS request_stats (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_code           VARCHAR(64) NOT NULL,
    period_start        TIMESTAMPTZ NOT NULL,
    period_type         VARCHAR(16) NOT NULL DEFAULT 'hour',  -- 'hour' | 'day'
    total_requests      BIGINT NOT NULL DEFAULT 0,
    blocked_requests    BIGINT NOT NULL DEFAULT 0,
    allowed_requests    BIGINT NOT NULL DEFAULT 0,
    stats_json          JSONB,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (host_code, period_start, period_type)
);
CREATE INDEX IF NOT EXISTS idx_request_stats_host_period ON request_stats(host_code, period_start DESC);
CREATE INDEX IF NOT EXISTS idx_request_stats_period_start ON request_stats(period_start DESC);

-- Notification configurations (sensitive fields encrypted at application layer)
CREATE TABLE IF NOT EXISTS notification_configs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(128) NOT NULL,
    host_code       VARCHAR(64),
    event_type      VARCHAR(64) NOT NULL,
    -- 'attack_detected' | 'cert_expiry' | 'high_traffic' | 'backend_down'
    channel_type    VARCHAR(32) NOT NULL,
    -- 'email' | 'webhook' | 'telegram'
    config_json     JSONB NOT NULL DEFAULT '{}',
    -- Note: config_json is encrypted with AES-256-GCM at the application layer
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    rate_limit_secs INTEGER NOT NULL DEFAULT 300,
    last_triggered  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_notification_configs_event_type ON notification_configs(event_type);
CREATE INDEX IF NOT EXISTS idx_notification_configs_host_code  ON notification_configs(host_code);

-- Notification log
CREATE TABLE IF NOT EXISTS notification_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_id       UUID REFERENCES notification_configs(id) ON DELETE SET NULL,
    event_type      VARCHAR(64) NOT NULL,
    channel_type    VARCHAR(32) NOT NULL,
    status          VARCHAR(32) NOT NULL,  -- 'sent' | 'failed' | 'rate_limited'
    message         TEXT,
    error_msg       TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_notification_log_config_id   ON notification_log(config_id);
CREATE INDEX IF NOT EXISTS idx_notification_log_created_at  ON notification_log(created_at DESC);
