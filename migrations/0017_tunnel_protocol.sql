-- Add `protocol` column to tunnels.
--
-- Widened from the originally-proposed VARCHAR(3) (tcp|udp|ws) to VARCHAR(8)
-- so the supported set can grow to quic/http/grpc without a follow-up ALTER.
-- The CHECK constraint enforces the closed set at the database boundary so a
-- direct INSERT (bypassing the API typed enum) still fails closed.
ALTER TABLE tunnels
    ADD COLUMN IF NOT EXISTS protocol VARCHAR(8) NOT NULL DEFAULT 'tcp';

-- IF NOT EXISTS makes the column add idempotent; the constraint add is not
-- automatically idempotent, so guard it with a DO block. Safe to re-run.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'tunnels_protocol_check'
    ) THEN
        ALTER TABLE tunnels
            ADD CONSTRAINT tunnels_protocol_check
            CHECK (protocol IN ('tcp', 'udp', 'ws', 'quic', 'http', 'grpc'));
    END IF;
END
$$;
