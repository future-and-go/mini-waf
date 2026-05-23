-- Change remote_ip from INET to TEXT.
--
-- Tradeoff note: INET provides network address validation and efficient GIST
-- indexing, but sqlx maps it to IpNetwork / IpAddr — not String. The Rust
-- model uses Option<String> to accommodate CIDR ranges and future freeform
-- overrides (e.g. "192.168.1.0/24"). Keeping INET would require a dedicated
-- sqlx type or a manual FromRow impl; TEXT is simpler and application-level
-- validation is sufficient for this optional override field.
--
-- Rollback: ALTER TABLE hosts ALTER COLUMN remote_ip TYPE INET USING remote_ip::INET;
ALTER TABLE hosts
    ALTER COLUMN remote_ip TYPE TEXT USING remote_ip::TEXT;
