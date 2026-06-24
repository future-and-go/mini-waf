// Static governance metadata for the 17 control-plane capabilities, derived from
// the E10 design doc's configuration-boundary table. UI-free leaf util so both
// the plane map (S6) and the catalog plane badges can import it without a cycle.
//
// - config: a startup/.toml knob governs whether the detector runs at all.
// - admin: an Admin UI page tunes the capability's rules/lists (deep-link target).
// - control is implicitly always true — all 17 are mode-toggleable.
// adminPath values are real nav-items routes so deep-links resolve.

export interface GovernanceEntry {
  feature: string;
  config: boolean;
  adminPath: string | null;
}

export const GOVERNANCE_MAP: GovernanceEntry[] = [
  { feature: "access_control", config: false, adminPath: "/ip-rules" },
  { feature: "injection_control", config: true, adminPath: "/rules-management" },
  { feature: "path_traversal", config: true, adminPath: "/rules-management" },
  { feature: "network_protection", config: true, adminPath: "/relay-intel" },
  { feature: "rate_limiting", config: true, adminPath: "/cc-protection" },
  { feature: "ddos_protection", config: true, adminPath: "/ddos-protection" },
  { feature: "bot_detection", config: true, adminPath: "/bot-management" },
  { feature: "owasp_rules", config: true, adminPath: "/rules-management" },
  { feature: "custom_rules", config: false, adminPath: "/custom-rules" },
  { feature: "geo_protection", config: true, adminPath: "/geo-restriction" },
  { feature: "data_protection", config: true, adminPath: "/sensitive-patterns" },
  { feature: "reputation", config: true, adminPath: "/crowdsec-settings" },
  { feature: "risk_assessment", config: true, adminPath: "/risk-scoring" },
  { feature: "velocity_control", config: true, adminPath: "/tx-velocity" },
  { feature: "device_intelligence", config: true, adminPath: "/device-fingerprinting" },
  { feature: "auth_protection", config: true, adminPath: null },
  { feature: "payload_protection", config: true, adminPath: null },
];

export const governanceFor = (feature: string): GovernanceEntry | undefined =>
  GOVERNANCE_MAP.find((e) => e.feature === feature);
