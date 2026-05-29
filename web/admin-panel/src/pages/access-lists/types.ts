// Shared types for the Access Lists admin page.

export interface AccessConfig {
  version: number;
  dry_run: boolean;
  ip_whitelist: string[];
  ip_blacklist: string[];
  host_whitelist: {
    critical: string[];
    high: string[];
    medium: string[];
    catch_all: string[];
  };
  tier_whitelist_mode: {
    critical: string;
    high: string;
    medium: string;
    catch_all: string;
  };
}

export type Tier = "critical" | "high" | "medium" | "catch_all";

export interface TestResult {
  verdict: "allow" | "block" | "bypass" | string;
  reason?: string;
}

export const TIERS: { key: Tier; label: string }[] = [
  { key: "critical", label: "Critical" },
  { key: "high", label: "High" },
  { key: "medium", label: "Medium" },
  { key: "catch_all", label: "Catch-All" },
];

export const WHITELIST_MODES = [
  { value: "full_bypass", label: "Full Bypass" },
  { value: "blacklist_only", label: "Blacklist Only" },
];

export const DEFAULT_CONFIG: AccessConfig = {
  version: 1,
  dry_run: false,
  ip_whitelist: [],
  ip_blacklist: [],
  host_whitelist: { critical: [], high: [], medium: [], catch_all: [] },
  tier_whitelist_mode: {
    critical: "blacklist_only",
    high: "blacklist_only",
    medium: "blacklist_only",
    catch_all: "blacklist_only",
  },
};

export function parseLines(raw: string): string[] {
  return raw
    .split(/[\n\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export function joinLines(arr: string[]): string {
  return arr.join("\n");
}

export function verdictColor(v: string): "green" | "red" | "default" {
  if (v === "allow" || v === "bypass") return "green";
  if (v === "block") return "red";
  return "default";
}

// Backend envelope: { success: true, data: <payload> } — unwrap to T or pass-through.
export const unwrap = <T>(raw: unknown): T | undefined =>
  raw && typeof raw === "object" && "data" in (raw as Record<string, unknown>)
    ? (raw as { data?: T }).data
    : (raw as T | undefined);
