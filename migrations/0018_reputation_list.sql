-- FR-042 / #60.6 — IP reputation editor.
--
-- Operator-curated list of IPs with a score in [-100, 100] and a provenance
-- tag (manual / crowdsec / community / feed). Soft-expiry via expires_at so
-- entries clean themselves up; unique on (ip, source) so the same source
-- cannot double-publish for the same IP.

CREATE TABLE IF NOT EXISTS reputation_list (
    id          BIGSERIAL PRIMARY KEY,
    ip          TEXT NOT NULL,
    score       INTEGER NOT NULL CHECK (score BETWEEN -100 AND 100),
    source      VARCHAR(32) NOT NULL
                CHECK (source IN ('manual', 'crowdsec', 'community', 'feed')),
    expires_at  TIMESTAMPTZ NOT NULL,
    notes       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (ip, source)
);

CREATE INDEX IF NOT EXISTS reputation_list_ip_idx      ON reputation_list (ip);
CREATE INDEX IF NOT EXISTS reputation_list_expires_idx ON reputation_list (expires_at);
