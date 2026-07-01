import type { TopEntry } from "../../types/api";

export interface GeoRule {
  id: number;
  iso_code: string;
  country_name?: string;
  action: "block" | "challenge" | "log" | "allow";
  scope: "global" | string;
  enabled: boolean;
  created_at?: string;
}

export interface LookupResult {
  iso_code: string;
  country_name: string;
  isp?: string;
}

export interface GeoStat {
  iso_code: string;
  country_name?: string;
  count: number;
}

export interface AddForm {
  iso_code: string;
  action: "block" | "challenge" | "log" | "allow";
  scope: string;
}

export interface GeoDistEntry {
  iso_code: string;
  country: string;
  count: number;
}

export interface GeoStatsResponse {
  top_countries: TopEntry[];
  top_cities: TopEntry[];
  top_isps: TopEntry[];
  country_distribution: GeoDistEntry[];
}

export const COUNTRY_MAP: Record<string, { name: string; flag: string }> = {
  CN: { name: "China", flag: "🇨🇳" },
  US: { name: "United States", flag: "🇺🇸" },
  RU: { name: "Russia", flag: "🇷🇺" },
  DE: { name: "Germany", flag: "🇩🇪" },
  FR: { name: "France", flag: "🇫🇷" },
  GB: { name: "United Kingdom", flag: "🇬🇧" },
  IN: { name: "India", flag: "🇮🇳" },
  BR: { name: "Brazil", flag: "🇧🇷" },
  JP: { name: "Japan", flag: "🇯🇵" },
  KR: { name: "South Korea", flag: "🇰🇷" },
  VN: { name: "Vietnam", flag: "🇻🇳" },
  TH: { name: "Thailand", flag: "🇹🇭" },
  TW: { name: "Taiwan", flag: "🇹🇼" },
  HK: { name: "Hong Kong", flag: "🇭🇰" },
  SG: { name: "Singapore", flag: "🇸🇬" },
  AU: { name: "Australia", flag: "🇦🇺" },
  CA: { name: "Canada", flag: "🇨🇦" },
  NL: { name: "Netherlands", flag: "🇳🇱" },
  SE: { name: "Sweden", flag: "🇸🇪" },
  NO: { name: "Norway", flag: "🇳🇴" },
  PL: { name: "Poland", flag: "🇵🇱" },
  UA: { name: "Ukraine", flag: "🇺🇦" },
  IR: { name: "Iran", flag: "🇮🇷" },
  KP: { name: "North Korea", flag: "🇰🇵" },
  PK: { name: "Pakistan", flag: "🇵🇰" },
  ID: { name: "Indonesia", flag: "🇮🇩" },
  NG: { name: "Nigeria", flag: "🇳🇬" },
  EG: { name: "Egypt", flag: "🇪🇬" },
  ZA: { name: "South Africa", flag: "🇿🇦" },
  MX: { name: "Mexico", flag: "🇲🇽" },
};

export const countryLabel = (iso: string, name?: string) => {
  const entry = COUNTRY_MAP[iso];
  const flag = entry?.flag ?? "🏳";
  const label = name ?? entry?.name ?? iso;
  return `${flag} ${label}`;
};

export const ACTION_OPTIONS = [
  { value: "block", label: "block" },
  { value: "challenge", label: "challenge" },
  { value: "log", label: "log" },
  { value: "allow", label: "allow" },
];
