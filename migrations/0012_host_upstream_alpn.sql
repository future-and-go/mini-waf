-- Add per-host upstream ALPN configuration (default h2h1).
--
-- BEHAVIOR CHANGE: existing hosts with ssl=true previously used Pingora's
-- hardcoded H1-only ALPN. After this migration they will advertise h2+http/1.1
-- (h2h1), enabling HTTP/2 negotiation with modern upstreams (CloudFront, etc.).
-- Operators who need the old H1-only behaviour must explicitly set upstream_alpn
-- to 'h1_only' on those hosts.
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS upstream_alpn TEXT NOT NULL DEFAULT 'h2h1';
