-- Change remote_ip from INET to TEXT.
--
-- NOTE: This is an unrelated cleanup bundled with the upstream-ALPN PR for
-- expediency. It should ideally be a standalone PR.
--
-- Tradeoff: INET provides validation + GIST indexing, but sqlx decodes INET
-- as IpNetwork/IpAddr, not String. The Rust model uses Option<String> so the
-- field can hold bare IPs, CIDR overrides, or remain null without an extra
-- FromRow impl. Application-level validation is sufficient for this optional
-- upstream-address override field (it is never queried by range).
--
-- Rollback: ALTER TABLE hosts ALTER COLUMN remote_ip TYPE INET USING remote_ip::INET;
ALTER TABLE hosts
    ALTER COLUMN remote_ip TYPE TEXT USING remote_ip::TEXT;
