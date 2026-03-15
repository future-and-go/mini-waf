-- PRX-WAF initial schema
-- PostgreSQL 18

-- Hosts / sites managed by the WAF
CREATE TABLE IF NOT EXISTS hosts (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code                    VARCHAR(32)  NOT NULL UNIQUE,
    host                    VARCHAR(253) NOT NULL,
    port                    INTEGER      NOT NULL DEFAULT 80,
    ssl                     BOOLEAN      NOT NULL DEFAULT FALSE,
    guard_status            BOOLEAN      NOT NULL DEFAULT TRUE,
    remote_host             VARCHAR(253) NOT NULL,
    remote_port             INTEGER      NOT NULL DEFAULT 8080,
    remote_ip               INET,
    cert_file               TEXT,
    key_file                TEXT,
    remarks                 TEXT,
    start_status            BOOLEAN      NOT NULL DEFAULT TRUE,
    exclude_url_log         TEXT,
    is_enable_load_balance  BOOLEAN      NOT NULL DEFAULT FALSE,
    load_balance_stage      INTEGER      NOT NULL DEFAULT 0,
    defense_json            JSONB,
    log_only_mode           BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at              TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_hosts_host ON hosts (host);
CREATE INDEX IF NOT EXISTS idx_hosts_code ON hosts (code);

-- IP allowlist
CREATE TABLE IF NOT EXISTS allow_ips (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_code   VARCHAR(32)  NOT NULL,
    ip_cidr     VARCHAR(50)  NOT NULL,
    remarks     TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_allow_ips_host_code ON allow_ips (host_code);

-- IP blocklist
CREATE TABLE IF NOT EXISTS block_ips (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_code   VARCHAR(32)  NOT NULL,
    ip_cidr     VARCHAR(50)  NOT NULL,
    remarks     TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_block_ips_host_code ON block_ips (host_code);

-- URL allowlist
CREATE TABLE IF NOT EXISTS allow_urls (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_code    VARCHAR(32)  NOT NULL,
    url_pattern  TEXT         NOT NULL,
    match_type   VARCHAR(20)  NOT NULL DEFAULT 'prefix',
    remarks      TEXT,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_allow_urls_host_code ON allow_urls (host_code);

-- URL blocklist
CREATE TABLE IF NOT EXISTS block_urls (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_code    VARCHAR(32)  NOT NULL,
    url_pattern  TEXT         NOT NULL,
    match_type   VARCHAR(20)  NOT NULL DEFAULT 'prefix',
    remarks      TEXT,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_block_urls_host_code ON block_urls (host_code);

-- Attack / security event logs
CREATE TABLE IF NOT EXISTS attack_logs (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_code        VARCHAR(32)  NOT NULL,
    host             VARCHAR(253) NOT NULL,
    client_ip        INET         NOT NULL,
    method           VARCHAR(10)  NOT NULL,
    path             TEXT         NOT NULL,
    query            TEXT,
    rule_id          VARCHAR(64),
    rule_name        VARCHAR(128) NOT NULL,
    action           VARCHAR(20)  NOT NULL,
    phase            VARCHAR(50)  NOT NULL,
    detail           TEXT,
    request_headers  JSONB,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_attack_logs_host_code  ON attack_logs (host_code);
CREATE INDEX IF NOT EXISTS idx_attack_logs_client_ip  ON attack_logs (client_ip);
CREATE INDEX IF NOT EXISTS idx_attack_logs_created_at ON attack_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_attack_logs_action     ON attack_logs (action);
