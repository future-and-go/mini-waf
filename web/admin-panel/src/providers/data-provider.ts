import type { DataProvider, BaseRecord, HttpError } from "@refinedev/core";
import { httpClient } from "../utils/axios";

// ─── Resource → REST path mapping ─────────────────────────────────────────────
// Refine resource names are kebab-case stable identifiers used in the routing
// layer. Many waf-api routes don't match Refine's CRUD convention exactly
// (e.g. `ip-rules` is split into `/api/allow-ips` and `/api/block-ips`).
// `customResources` maps the irregular ones; everything else falls back to
// `/api/${resource}`. Custom helpers below handle the dual-list resources.

const customResourceMap: Record<string, string> = {
  hosts: "/api/hosts",
  "custom-rules": "/api/custom-rules",
  certificates: "/api/certificates",
  "security-events": "/api/security-events",
  "attack-logs": "/api/attack-logs",
  notifications: "/api/notifications",
  "lb-backends": "/api/lb-backends",
  "bot-patterns": "/api/bot-patterns",
  "rule-sources": "/api/rule-sources",
  "registry-rules": "/api/rules/registry",
  "crowdsec-decisions": "/api/crowdsec/decisions",
  // Dual-list IP/URL: callers must use `allow-ips` / `block-ips` etc. directly.
  "allow-ips": "/api/allow-ips",
  "block-ips": "/api/block-ips",
  "allow-urls": "/api/allow-urls",
  "block-urls": "/api/block-urls",
};

const endpointFor = (resource: string): string =>
  customResourceMap[resource] ?? `/api/${resource}`;

// ─── Envelope unwrapping ──────────────────────────────────────────────────────
// waf-api responds in three shapes depending on handler:
//   1. { data: T[], total: N }   → list endpoints with pagination
//   2. { data: T }                → most CRUD endpoints
//   3. T                          → cluster/crowdsec raw responses
// We try (1) → (2) → (3) in order without guessing.
const unwrap = <T = unknown>(body: unknown): { data: T; total?: number } => {
  if (body && typeof body === "object" && "data" in body) {
    const env = body as { data: T; total?: number };
    return { data: env.data, total: env.total };
  }
  return { data: body as T };
};

const toHttpError = (err: unknown): HttpError => {
  const axiosErr = err as {
    response?: { status?: number; data?: { error?: string; message?: string } };
    message?: string;
  };
  return {
    message:
      axiosErr.response?.data?.error ??
      axiosErr.response?.data?.message ??
      axiosErr.message ??
      "Network error",
    statusCode: axiosErr.response?.status ?? 500,
  };
};

// ─── Data provider ────────────────────────────────────────────────────────────
// Method bodies use `BaseRecord` for the unwrapped axios payload then return
// types are widened via `as never` casts. The runtime cannot honour the
// caller's generic constraint anyway — the cast is the conventional way to
// satisfy Refine's `<TData extends BaseRecord>` parameter without sprinkling
// `any` through call sites.
export const dataProvider: DataProvider = {
  getApiUrl: () => "/api",

  // List with optional pagination (`?page=N&page_size=M` matches SecurityEvents
  // contract). Filters are flattened to query params.
  getList: async ({ resource, pagination, filters, meta }) => {
    const url = endpointFor(resource);
    const params: Record<string, unknown> = { ...(meta?.params ?? {}) };

    if (pagination?.mode !== "off") {
      const page = pagination?.currentPage ?? 1;
      const pageSize = pagination?.pageSize ?? 20;
      params.page = page;
      params.page_size = pageSize;
    }

    for (const f of filters ?? []) {
      if ("field" in f && f.value !== undefined && f.value !== "") {
        params[f.field] = f.value;
      }
    }

    try {
      const resp = await httpClient.get(url, { params });
      const { data, total } = unwrap<BaseRecord[]>(resp.data);
      const list = Array.isArray(data) ? data : [];
      return {
        data: list as never,
        total: total ?? list.length,
      };
    } catch (err) {
      throw toHttpError(err);
    }
  },

  getOne: async ({ resource, id, meta }) => {
    const url = `${endpointFor(resource)}/${id}`;
    try {
      const resp = await httpClient.get(url, { params: meta?.params });
      return { data: unwrap<BaseRecord>(resp.data).data as never };
    } catch (err) {
      throw toHttpError(err);
    }
  },

  create: async ({ resource, variables, meta }) => {
    const url = endpointFor(resource);
    try {
      const resp = await httpClient.post(url, variables, {
        params: meta?.params,
      });
      return { data: unwrap<BaseRecord>(resp.data).data as never };
    } catch (err) {
      throw toHttpError(err);
    }
  },

  update: async ({ resource, id, variables, meta }) => {
    const url = `${endpointFor(resource)}/${id}`;
    const method = (meta?.method as "put" | "patch") ?? "put";
    try {
      const resp = await httpClient.request({
        url,
        method,
        data: variables,
        params: meta?.params,
      });
      return { data: unwrap<BaseRecord>(resp.data).data as never };
    } catch (err) {
      throw toHttpError(err);
    }
  },

  deleteOne: async ({ resource, id, meta }) => {
    const url = `${endpointFor(resource)}/${id}`;
    try {
      const resp = await httpClient.delete(url, { params: meta?.params });
      return { data: unwrap<BaseRecord>(resp.data).data as never };
    } catch (err) {
      throw toHttpError(err);
    }
  },

  // Raw escape hatch — useful for action endpoints that don't fit CRUD
  // (e.g. POST /api/reload, POST /api/notifications/:id/test).
  custom: async ({ url, method, payload, query, headers }) => {
    try {
      const resp = await httpClient.request({
        url,
        method,
        data: payload,
        params: query,
        headers,
      });
      return { data: unwrap(resp.data).data as never };
    } catch (err) {
      throw toHttpError(err);
    }
  },
};
