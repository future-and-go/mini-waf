import {
  DashboardOutlined,
  GlobalOutlined,
  SafetyOutlined,
  LinkOutlined,
  AlertOutlined,
  ContainerOutlined,
  FileTextOutlined,
  LockOutlined,
  SafetyCertificateOutlined,
  BellOutlined,
  SettingOutlined,
  ClusterOutlined,
  KeyOutlined,
  SyncOutlined,
  CloudOutlined,
  StopOutlined,
  BarChartOutlined,
  BookOutlined,
  BranchesOutlined,
  RobotOutlined,
  ThunderboltOutlined,
  AuditOutlined,
  ApartmentOutlined,
  SecurityScanOutlined,
  ScanOutlined,
  ExperimentOutlined,
  FundOutlined,
  ApiOutlined,
  ShareAltOutlined,
  EyeInvisibleOutlined,
  FilterOutlined,
} from "@ant-design/icons";
import type { ComponentType } from "react";

export interface NavItem {
  key: string;
  i18nKey: string;
  path: string;
  icon: ComponentType;
  section?: string;
}

// Single source of truth for sidebar layout. Order = render order.
export const navItems: NavItem[] = [
  // nav.overview
  { key: "dashboard", i18nKey: "nav.dashboard", path: "/dashboard", icon: DashboardOutlined },
  { key: "hosts", i18nKey: "nav.hosts", path: "/hosts", icon: GlobalOutlined },
  { key: "security-events", i18nKey: "nav.securityEvents", path: "/security-events", icon: AlertOutlined },
  { key: "logs", i18nKey: "nav.logs", path: "/logs", icon: ContainerOutlined },

  // nav.protection
  { key: "tier-policies", i18nKey: "nav.tierPolicies", path: "/tier-policies", icon: ApartmentOutlined, section: "nav.protection" },
  { key: "access-lists", i18nKey: "nav.accessLists", path: "/access-lists", icon: LockOutlined, section: "nav.protection" },
  { key: "ddos-protection", i18nKey: "nav.ddosProtection", path: "/ddos-protection", icon: ThunderboltOutlined, section: "nav.protection" },
  { key: "challenge-engine", i18nKey: "nav.challengeEngine", path: "/challenge-engine", icon: ExperimentOutlined, section: "nav.protection" },
  { key: "ip-rules", i18nKey: "nav.ipRules", path: "/ip-rules", icon: SafetyOutlined, section: "nav.protection" },
  { key: "url-rules", i18nKey: "nav.urlRules", path: "/url-rules", icon: LinkOutlined, section: "nav.protection" },

  // nav.detection
  { key: "rules-management", i18nKey: "nav.ruleManager", path: "/rules-management", icon: BookOutlined, section: "nav.detection" },
  { key: "custom-rules", i18nKey: "nav.customRules", path: "/custom-rules", icon: FileTextOutlined, section: "nav.detection" },
  { key: "rule-sources", i18nKey: "nav.ruleSources", path: "/rule-sources", icon: BranchesOutlined, section: "nav.detection" },
  { key: "rule-analytics", i18nKey: "nav.ruleAnalytics", path: "/rule-analytics", icon: BarChartOutlined, section: "nav.detection" },
  { key: "bot-management", i18nKey: "nav.botDetection", path: "/bot-management", icon: RobotOutlined, section: "nav.detection" },

  // nav.intel
  { key: "device-fingerprinting", i18nKey: "nav.deviceFingerprinting", path: "/device-fingerprinting", icon: ScanOutlined, section: "nav.intel" },
  { key: "relay-intel", i18nKey: "nav.relayIntel", path: "/relay-intel", icon: BranchesOutlined, section: "nav.intel" },
  { key: "risk-scoring", i18nKey: "nav.riskScoring", path: "/risk-scoring", icon: SecurityScanOutlined, section: "nav.intel" },
  { key: "geo-restriction", i18nKey: "nav.geoRestriction", path: "/geo-restriction", icon: GlobalOutlined, section: "nav.intel" },

  // nav.outbound
  { key: "response-filtering", i18nKey: "nav.responseFiltering", path: "/response-filtering", icon: EyeInvisibleOutlined, section: "nav.outbound" },
  { key: "sensitive-patterns", i18nKey: "nav.sensitivePatterns", path: "/sensitive-patterns", icon: FilterOutlined, section: "nav.outbound" },

  // nav.fraud
  { key: "tx-velocity", i18nKey: "nav.txVelocity", path: "/tx-velocity", icon: AuditOutlined, section: "nav.fraud" },

  // nav.cluster
  { key: "cluster", i18nKey: "nav.clusterOverview", path: "/cluster", icon: ClusterOutlined, section: "nav.cluster" },
  { key: "cluster-tokens", i18nKey: "nav.clusterTokens", path: "/cluster/tokens", icon: KeyOutlined, section: "nav.cluster" },
  { key: "cluster-sync", i18nKey: "nav.clusterSync", path: "/cluster/sync", icon: SyncOutlined, section: "nav.cluster" },

  // nav.crowdsec
  { key: "crowdsec-settings", i18nKey: "nav.csSettings", path: "/crowdsec-settings", icon: CloudOutlined, section: "nav.crowdsec" },
  { key: "crowdsec-decisions", i18nKey: "nav.csDecisions", path: "/crowdsec-decisions", icon: StopOutlined, section: "nav.crowdsec" },
  { key: "crowdsec-stats", i18nKey: "nav.csStats", path: "/crowdsec-stats", icon: BarChartOutlined, section: "nav.crowdsec" },

  // nav.cache
  { key: "cache", i18nKey: "nav.cacheDashboard", path: "/cache", icon: FundOutlined, section: "nav.cache" },

  // nav.extensions
  { key: "plugins", i18nKey: "nav.plugins", path: "/plugins", icon: ApiOutlined, section: "nav.extensions" },
  { key: "tunnels", i18nKey: "nav.tunnels", path: "/tunnels", icon: ShareAltOutlined, section: "nav.extensions" },

  // nav.system
  { key: "certificates", i18nKey: "nav.certificates", path: "/certificates", icon: SafetyCertificateOutlined, section: "nav.system" },
  { key: "cc-protection", i18nKey: "nav.ccProtection", path: "/cc-protection", icon: SecurityScanOutlined, section: "nav.system" },
  { key: "notifications", i18nKey: "nav.notifications", path: "/notifications", icon: BellOutlined, section: "nav.system" },
  { key: "settings", i18nKey: "nav.settings", path: "/settings", icon: SettingOutlined, section: "nav.system" },
];
