import axios, { type AxiosInstance, type AxiosError } from "axios";

const TOKEN_KEY = "access_token";
const REFRESH_KEY = "refresh_token";

// Singleton axios instance shared by data + auth providers.
//   - Bearer token attached on every request
//   - 401 → clears tokens; auth provider check() then redirects to /login
//   - Base URL is "/" because all backend paths are absolute under /api/*
export const httpClient: AxiosInstance = axios.create({
  baseURL: "/",
  timeout: 15000,
});

httpClient.interceptors.request.use((config) => {
  const token = localStorage.getItem(TOKEN_KEY);
  if (token) {
    config.headers.set("Authorization", `Bearer ${token}`);
  }
  return config;
});

httpClient.interceptors.response.use(
  (resp) => resp,
  (err: AxiosError) => {
    if (err.response?.status === 401) {
      localStorage.removeItem(TOKEN_KEY);
      localStorage.removeItem(REFRESH_KEY);
    }
    return Promise.reject(err);
  },
);

export const tokenStorage = {
  get: () => localStorage.getItem(TOKEN_KEY),
  getRefresh: () => localStorage.getItem(REFRESH_KEY),
  set: (access: string, refresh: string) => {
    localStorage.setItem(TOKEN_KEY, access);
    localStorage.setItem(REFRESH_KEY, refresh);
  },
  clear: () => {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(REFRESH_KEY);
  },
  parseJwt: (token: string): Record<string, unknown> | null => {
    try {
      return JSON.parse(atob(token.split(".")[1]));
    } catch {
      return null;
    }
  },
};
