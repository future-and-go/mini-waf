-- Persist the protection tier (Critical | High | Medium | CatchAll) per security
-- event so the Security Logs page can filter by tier. Forward-only: rows written
-- before this migration keep tier = NULL (excluded when a tier filter is active).
ALTER TABLE security_events
    ADD COLUMN IF NOT EXISTS tier TEXT;

-- Non-concurrent build: takes a brief write-blocking lock for the build duration.
-- Accepted at benchmark/dev scale (small table). Re-evaluate (split out + build
-- CONCURRENTLY via a maintenance task) before any large-table deploy.
CREATE INDEX IF NOT EXISTS idx_security_events_tier ON security_events (tier);
