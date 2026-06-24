import { useCustom } from "@refinedev/core";
import type { CapabilitiesResponse } from "../types/api";
import { ENFORCEMENT_ROUTES } from "../providers/enforcement-provider";

// Stable queryKey so the console page and the header mode pill share one fetch
// instead of issuing two parallel requests for the same capabilities snapshot.
export const ENFORCEMENT_CAPS_QUERY_KEY = ["enforcement-capabilities"];

// Shared capabilities query. interop-disabled backends answer 404, surfaced via
// `query.error.statusCode === 404` (same pattern as cluster pages). retry:false
// keeps that detection immediate.
export const useEnforcementCapabilities = () =>
  useCustom<CapabilitiesResponse>({
    url: ENFORCEMENT_ROUTES.capabilities,
    method: "get",
    queryOptions: {
      staleTime: 3_000,
      refetchInterval: 10_000,
      queryKey: ENFORCEMENT_CAPS_QUERY_KEY,
      retry: false,
    },
  });
