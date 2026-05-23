-- Widen upstream_alpn from VARCHAR(8) to TEXT.
--
-- VARCHAR(8) is tight (max current value "h2_only" = 7 chars, zero headroom).
-- Future values such as "http1_only" (10 chars) or "h2h1_h3" would silently
-- truncate. TEXT has no upper bound and is semantically identical in Postgres
-- for this column (no constraint was relying on the length).
ALTER TABLE hosts
    ALTER COLUMN upstream_alpn TYPE TEXT;
