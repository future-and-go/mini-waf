import type { AuthProvider } from "@refinedev/core";
import { httpClient, tokenStorage } from "../utils/axios";
import type { Envelope, LoginResponse } from "../types/api";

// JWT Bearer auth against waf-api's `/api/auth/*` endpoints.
//   login   → POST /api/auth/login   { username, password } → { data: { access_token, refresh_token } }
//   logout  → POST /api/auth/logout  { refresh_token }
//   refresh → POST /api/auth/refresh { refresh_token } → new tokens
//
// Tokens are persisted in localStorage; the axios interceptor reads from there
// for every subsequent request. We do not auto-refresh on 401 here — the
// interceptor clears tokens and `check()` redirects to /login.

export const authProvider: AuthProvider = {
  login: async ({ username, password }) => {
    try {
      const resp = await httpClient.post<Envelope<LoginResponse>>(
        "/api/auth/login",
        { username, password },
      );
      const data = resp.data.data;
      tokenStorage.set(data.access_token, data.refresh_token);
      return { success: true, redirectTo: "/" };
    } catch (err: unknown) {
      const e = err as { response?: { data?: { error?: string } }; message?: string };
      return {
        success: false,
        error: {
          name: "LoginError",
          message:
            e.response?.data?.error ?? e.message ?? "Invalid credentials",
        },
      };
    }
  },

  logout: async () => {
    const refresh = tokenStorage.getRefresh();
    if (refresh) {
      try {
        await httpClient.post("/api/auth/logout", { refresh_token: refresh });
      } catch {
        // logout best-effort; clear tokens regardless
      }
    }
    tokenStorage.clear();
    return { success: true, redirectTo: "/login" };
  },

  check: async () => {
    if (tokenStorage.get()) {
      return { authenticated: true };
    }
    return {
      authenticated: false,
      logout: true,
      redirectTo: "/login",
      error: { name: "NotAuthenticated", message: "Login required" },
    };
  },

  getIdentity: async () => {
    const token = tokenStorage.get();
    if (!token) return null;
    const claims = tokenStorage.parseJwt(token);
    if (!claims) return null;
    return {
      id: claims.sub ?? claims.username ?? "user",
      name: (claims.username as string) ?? "user",
      role: (claims.role as string) ?? "admin",
    };
  },

  onError: async (error) => {
    if (error?.statusCode === 401) {
      tokenStorage.clear();
      return { logout: true, redirectTo: "/login" };
    }
    return {};
  },
};
