-- Change remote_ip from INET to TEXT so the Rust model (Option<String>) decodes correctly.
ALTER TABLE hosts
    ALTER COLUMN remote_ip TYPE TEXT USING remote_ip::TEXT;
