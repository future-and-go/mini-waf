-- Add protocol column to tunnels (tcp | udp | ws, default tcp)
ALTER TABLE tunnels ADD COLUMN IF NOT EXISTS protocol VARCHAR(3) NOT NULL DEFAULT 'tcp';
