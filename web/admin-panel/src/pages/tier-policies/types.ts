// Shared types for the Tier Policies admin page.

export interface TierPolicy {
  fail_mode: "close" | "open";
  ddos_threshold_rps: number;
  cache_policy: "no_cache" | "short_ttl" | "aggressive" | "default";
  risk_thresholds: { allow: number; challenge: number; block: number };
}

export interface ClassifierRule {
  id: number;
  priority: number;
  tier: string;
  host_match?: string;
  path_match?: string;
  methods?: string[];
}

export interface TierConfig {
  policies: {
    critical: TierPolicy;
    high: TierPolicy;
    medium: TierPolicy;
    catch_all: TierPolicy;
  };
  classifier_rules: ClassifierRule[];
}

export interface DryRunResponse {
  matched_tier: string;
  matched_rule_id?: number;
}

export const TIER_KEYS = ["critical", "high", "medium", "catch_all"] as const;
export type TierKey = (typeof TIER_KEYS)[number];

export const TIER_COLOR: Record<TierKey, string> = {
  critical: "#f5222d",
  high: "#fa8c16",
  medium: "#fadb14",
  catch_all: "#1677ff",
};

export const HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

export const DEFAULT_POLICY: TierPolicy = {
  fail_mode: "close",
  ddos_threshold_rps: 100,
  cache_policy: "default",
  risk_thresholds: { allow: 20, challenge: 60, block: 85 },
};

export const DEFAULT_CONFIG: TierConfig = {
  policies: {
    critical: { ...DEFAULT_POLICY, ddos_threshold_rps: 50, cache_policy: "no_cache" },
    high: { ...DEFAULT_POLICY, ddos_threshold_rps: 200 },
    medium: { ...DEFAULT_POLICY, ddos_threshold_rps: 500, cache_policy: "short_ttl" },
    catch_all: { ...DEFAULT_POLICY, fail_mode: "open", ddos_threshold_rps: 1000, cache_policy: "aggressive" },
  },
  classifier_rules: [],
};
