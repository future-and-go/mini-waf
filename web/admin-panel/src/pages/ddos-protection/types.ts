// Shared types for the DDoS Protection admin page.

export interface DdosConfig {
  enabled: boolean;
  per_ip: { threshold_rps: number; window_secs: number };
  per_fingerprint: { threshold_rps: number; window_secs: number };
  ban_durations_secs: number[];
  store: { backend: "memory" | "redis"; redis_url?: string };
}

export interface BanEntry {
  ip: string;
  expires_at_ms: number;
  ttl_remaining_secs: number;
}

export interface DdosMetrics {
  active_bans: number;
  bursts_total: number;
  bursts_per_ip: number;
  bursts_per_fp: number;
  bursts_per_tier: number;
  bans_total: number;
  store_errors: number;
  degrade_events: number;
}

export const DEFAULT_CONFIG: DdosConfig = {
  enabled: true,
  per_ip: { threshold_rps: 100, window_secs: 10 },
  per_fingerprint: { threshold_rps: 200, window_secs: 10 },
  ban_durations_secs: [60, 300, 3600],
  store: { backend: "memory" },
};

// Backend envelope: { success: true, data: <payload> } — unwrap to T or pass-through.
export const unwrap = <T>(raw: unknown): T | undefined =>
  raw && typeof raw === "object" && "data" in (raw as Record<string, unknown>)
    ? (raw as { data?: T }).data
    : (raw as T | undefined);
