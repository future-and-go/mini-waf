-- Persist the effective enforcement mode (enforce | log_only) per security event.
-- Sourced from the WAF decision mode so console state and event records agree.
ALTER TABLE security_events
    ADD COLUMN IF NOT EXISTS waf_mode TEXT NOT NULL DEFAULT 'enforce';
