import { httpClient } from "../utils/axios";
import type {
  CapabilitiesResponse,
  SetProfileBody,
  SetProfileResponse,
  ResetStateResponse,
  FlushCacheResponse,
} from "../types/api";

// Single source of truth for the JWT-guarded control-plane routes. The browser
// only ever talks to these; it never holds X-Benchmark-Secret. Flip these here
// if the proxy path ever changes. UI surfaces use useCustom/useCustomMutation
// against these same paths so they share React-Query caching; the functions
// below are typed direct callers (smoke checks, non-cached calls).
export const ENFORCEMENT_ROUTES = {
  capabilities: "/api/enforcement/capabilities",
  setProfile: "/api/enforcement/set-profile",
  resetState: "/api/enforcement/reset-state",
  flushCache: "/api/enforcement/flush-cache",
} as const;

export const enforcementProvider = {
  async getCapabilities(): Promise<CapabilitiesResponse> {
    const resp = await httpClient.get<CapabilitiesResponse>(ENFORCEMENT_ROUTES.capabilities);
    return resp.data;
  },
  async setProfile(body: SetProfileBody): Promise<SetProfileResponse> {
    const resp = await httpClient.post<SetProfileResponse>(ENFORCEMENT_ROUTES.setProfile, body);
    return resp.data;
  },
  async resetState(): Promise<ResetStateResponse> {
    const resp = await httpClient.post<ResetStateResponse>(ENFORCEMENT_ROUTES.resetState, {});
    return resp.data;
  },
  async flushCache(): Promise<FlushCacheResponse> {
    const resp = await httpClient.post<FlushCacheResponse>(ENFORCEMENT_ROUTES.flushCache, {});
    return resp.data;
  },
};
