// Mirrors the response envelope used by waf-api Rust handlers.
//   Most endpoints wrap the payload in { data: T }; some pagination endpoints
//   add { total }; cluster/crowdsec endpoints respond raw (no envelope).
// Refine's data provider unwraps these two patterns transparently.

export interface Envelope<T> {
  data: T;
  total?: number;
  message?: string;
}

export interface PageResponse<T> {
  data: T[];
  total: number;
}

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  expires_in?: number;
  username?: string;
}

// ─── Domain models (shape used by views — unknown fields preserved) ──────────

export type UpstreamAlpn = "h2h1" | "h1_only" | "h2_only";

export interface DefenseJson {
  bot?: boolean;
  sqli?: boolean;
  xss?: boolean;
  scan?: boolean;
  rce?: boolean;
  sensitive?: boolean;
  dir_traversal?: boolean;
  owasp_set?: boolean;
  owasp_paranoia?: number;
  cc?: boolean;
  cc_rps?: number;
  cc_burst?: number;
  cc_ban_threshold?: number;
  cc_ban_duration_secs?: number;
}

export interface Host {
  id: string;
  host: string;
  port: number;
  ssl: boolean;
  guard_status: boolean;
  remote_host: string;
  remote_port: number;
  start_status: boolean;
  log_only_mode?: boolean;
  remarks?: string;
  upstream_alpn: UpstreamAlpn;
  upstream_skip_ssl_verify: boolean;
  defense_json?: DefenseJson | null;
}

export interface IpRule {
  id: string;
  ip_cidr: string;
  host_code: string;
  note?: string;
}

export interface UrlRule {
  id: string;
  url_pattern: string;
  host_code: string;
  match_type?: string;
}

// ── Operator catalog (mirrors waf-engine::Operator serde rename_all="snake_case") ──
export type RuleOperator =
  | "eq" | "ne" | "contains" | "not_contains"
  | "starts_with" | "ends_with"
  | "regex" | "wildcard"
  | "in_list" | "not_in_list"
  | "cidr_match"
  | "gt" | "lt" | "gte" | "lte";

// ── Field catalog (mirrors ConditionField, including newtypes) ──
export type SimpleField =
  | "ip" | "path" | "query" | "method" | "body"
  | "host" | "user_agent" | "content_type" | "content_length"
  | "geo_country" | "geo_iso" | "geo_province" | "geo_city" | "geo_isp";

// Newtypes: `{header: "x-foo"}` / `{cookie: "session"}` / `{cookie: null}` (legacy)
export type HeaderField = { header: string };
export type CookieField = { cookie: string | null };
export type ConditionField = SimpleField | HeaderField | CookieField;

export type ConditionValue = string | number | string[];

export interface Condition {
  field: ConditionField;
  operator: RuleOperator;
  value: ConditionValue;
}

// ── ConditionNode tree: untagged discriminated by key presence ──
export type ConditionNode =
  | { and: ConditionNode[] }
  | { or: ConditionNode[] }
  | { not: ConditionNode }
  | Condition; // bare leaf

export type ConditionOp = "and" | "or";
export type RuleAction = "block" | "allow" | "log" | "challenge";

export interface CustomRule {
  id: string;
  host_code: string;
  name: string;
  description?: string | null;
  priority: number;
  enabled: boolean;
  condition_op: ConditionOp;
  /** Flat legacy conditions (empty `[]` when match_tree is used). */
  conditions: Condition[];
  /** Structured condition tree — always present at top-level after API normalisation. */
  match_tree?: ConditionNode | null;
  action: RuleAction;
  action_status: number;
  action_msg?: string | null;
  script?: string | null;
  created_at?: string;
  updated_at?: string;
}

export interface CreateCustomRulePayload {
  host_code: string;
  name: string;
  description?: string | null;
  priority?: number;
  enabled?: boolean;
  condition_op?: ConditionOp;
  conditions?: Condition[];
  match_tree?: ConditionNode | null;
  action?: RuleAction;
  action_status?: number;
  action_msg?: string | null;
  script?: string | null;
}

// Tree bounds — must match engine.rs constants MAX_TREE_DEPTH / MAX_TREE_LEAVES
export const MAX_TREE_DEPTH = 16;
export const MAX_TREE_LEAVES = 256;

export interface Certificate {
  id: string;
  domain: string;
  host_code: string;
  issuer?: string;
  not_after?: string;
  status: string;
}

export interface SecurityEvent {
  id: string;
  host_code: string;
  created_at: string;
  client_ip: string;
  method: string;
  path: string;
  rule_name: string;
  rule_id: string | null;
  action: string;
  detail: string | null;
  geo_info: {
    country?: string;
    province?: string;
    city?: string;
    isp?: string;
    iso_code?: string;
  } | null;
  category?: string;
  country?: string;
}

// Derive attack category from rule_id prefix — mirrors waf-storage CASE expression.
export const deriveCategory = (ruleId?: string | null): string => {
  if (!ruleId) return "other";
  const prefixMap: Array<[RegExp, string]> = [
    [/^SQLI-/, "sqli"], [/^XSS-/, "xss"], [/^RCE-/, "rce"],
    [/^TRAV-/, "path-traversal"], [/^SCAN-/, "scanner"],
    [/^BOT-/, "bot"], [/^CC-/, "cc-ddos"],
    [/^SSRF-/, "ssrf"],
    [/^ADV-SSRF/, "ssrf"], [/^ADV-SSTI/, "ssti"], [/^ADV-/, "advanced"],
    [/^CRS-RESP/, "data-leakage"], [/^CRS-/, "owasp-crs"],
    [/^API-MASS/, "mass-assignment"], [/^API-/, "api-security"],
    [/^MODSEC-RESP/, "web-shell"], [/^MODSEC-/, "modsecurity"],
    [/^CVE-/, "cve"], [/^GEO-/, "geo-blocking"], [/^CUSTOM-/, "custom"],
    [/^IP-/, "ip-rule"], [/^URL-/, "url-rule"],
    [/^SENS-/, "sensitive-data"], [/^HOTLINK-/, "anti-hotlink"],
    [/^OWASP-942/, "sqli"], [/^OWASP-941/, "xss"],
    [/^OWASP-930/, "lfi"], [/^OWASP-931/, "rfi"],
    [/^OWASP-932/, "rce"], [/^OWASP-933/, "php-injection"],
    [/^OWASP-913/, "scanner"],
  ];
  for (const [re, cat] of prefixMap) if (re.test(ruleId)) return cat;
  return "other";
};

export interface NotificationConfig {
  id: string;
  name: string;
  channel_type: string;
  event_type: string;
  host_code?: string;
  last_triggered?: string;
}

export interface LbBackend {
  id: string;
  host_code: string;
  backend_host: string;
  backend_port: number;
  is_healthy: boolean;
}

export interface BotPattern {
  id: string;
  name: string;
  pattern: string;
  action: string;
  tags?: string[];
  enabled: boolean;
  source?: string;
}

export interface RegistryRule {
  id: string;
  name: string;
  description?: string;
  category: string;
  source: string;
  enabled: boolean;
  action: string;
  severity?: string;
  pattern?: string | null;
  tags?: string[];
  file?: string;
}

export interface RuleSource {
  name: string;
  type: string;
  url?: string;
  path?: string;
  format: string;
  enabled: boolean;
  lastUpdated?: string;
  error?: string;
}

export interface CrowdsecDecision {
  id: number;
  origin: string;
  scope: string;
  value: string;
  type_: string;
  scenario: string;
  duration?: string;
}

export interface ClusterNode {
  node_id: string;
  role: string;
  health: string;
  addr?: string;
  is_self: boolean;
  term: number;
  rules_version: number;
  config_version: number;
  last_seen_ms?: number;
}

export interface ClusterStatus {
  total_nodes: number;
  role: string;
  term: number;
  rules_version: number;
  config_version: number;
  listen_addr: string;
  nodes: ClusterNode[];
}

export interface SystemStatus {
  version: string;
  hosts: number;
  total_requests: number;
  rules?: {
    allow_ips?: number;
    block_ips?: number;
    allow_urls?: number;
    block_urls?: number;
  };
}

export interface StatsOverview {
  total_requests: number;
  total_blocked: number;
  total_allowed: number;
  block_rate: number;
  hosts_count: number;
  unique_attackers: number;
  top_ips: TopEntry[];
  top_rules: TopEntry[];
  top_countries: TopEntry[];
  top_isps: TopEntry[];
  category_breakdown: TopEntry[];
  action_breakdown: TopEntry[];
  recent_events: RecentEvent[];
  crowdsec_enabled?: boolean;
}

export interface TopEntry {
  key: string;
  count: number;
}

export interface RecentEvent {
  ts: string;
  client_ip: string;
  host_code: string;
  method: string;
  path: string;
  rule_id?: string;
  rule_name: string;
  action: string;
  category: string;
  country?: string;
}

export interface TrafficPoint {
  ts: string;
  total: number;
  blocked: number;
}

export interface HeatmapCell {
  path: string;
  category: string;
  count: number;
}

export interface HeatmapMetadata {
  total_events: number;
  paths_sampled: number;
  categories_total: number;
  window_hours: number;
  timestamp: string;
}

export interface EndpointHeatmap {
  cells: HeatmapCell[];
  metadata: HeatmapMetadata;
}
