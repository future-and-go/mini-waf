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

export interface CustomRule {
  id: string;
  name: string;
  host_code: string;
  priority: number;
  action: string;
  enabled: boolean;
  script: string;
}

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
  created_at: string;
  client_ip: string;
  method: string;
  path: string;
  rule_name: string;
  rule_id?: string;
  action: string;
  category?: string;
  country?: string;
}

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
  pattern?: string;
  tags?: string[];
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
