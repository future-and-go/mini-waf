-- Widen upstream_alpn from VARCHAR(8) to TEXT.
--
-- VARCHAR(8) created in 0012 is too tight: max current value "h2_only" = 7
-- chars leaves no room for future values (e.g. "http1_only" = 10 chars).
-- TEXT has no upper bound and is semantically identical in Postgres for this
-- column (no length constraint was relied upon).
ALTER TABLE hosts
    ALTER COLUMN upstream_alpn TYPE TEXT;
