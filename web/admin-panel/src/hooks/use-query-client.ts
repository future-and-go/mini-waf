import { useMemo } from "react";
import { QueryClient } from "@tanstack/react-query";

// Tiered cache strategy for a "data-heavy + light refresh" admin:
//   - Default queries: 30s stale window, 5min GC, no refetch on focus
//   - Hot queries override staleTime/refetchInterval per useList call
// Refine v4 reuses any QueryClient passed via <Refine options.reactQuery.clientConfig>.

export const useQueryClient = (): QueryClient =>
  useMemo(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            staleTime: 30_000,
            gcTime: 5 * 60_000,
            refetchOnWindowFocus: false,
            refetchOnReconnect: true,
            retry: 1,
          },
          mutations: {
            retry: 0,
          },
        },
      }),
    [],
  );
