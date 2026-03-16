-- Phase 2: Security events table for attack detection logs
CREATE TABLE IF NOT EXISTS security_events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_code   TEXT NOT NULL,
    client_ip   TEXT NOT NULL,
    method      TEXT NOT NULL,
    path        TEXT NOT NULL,
    rule_id     TEXT,
    rule_name   TEXT NOT NULL,
    action      TEXT NOT NULL,
    detail      TEXT,
    geo_info    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_events_host_code  ON security_events (host_code);
CREATE INDEX IF NOT EXISTS idx_security_events_client_ip  ON security_events (client_ip);
CREATE INDEX IF NOT EXISTS idx_security_events_rule_name  ON security_events (rule_name);
CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_action     ON security_events (action);
