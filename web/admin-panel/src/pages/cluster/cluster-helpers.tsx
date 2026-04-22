import type { TFunction } from "i18next";

// Shared label/colour helpers for the four Cluster pages.
// Pulled into one file so role/health classification stays consistent
// across overview, node-detail, and sync screens.

export const roleLabel = (role: string, t: TFunction): string =>
  ({ main: t("cluster.main"), worker: t("cluster.worker"), candidate: t("cluster.candidate") } as Record<string, string>)[role] ??
  role;

export const roleColor = (role: string): string => {
  if (role === "main") return "#389e0d";
  if (role === "candidate") return "#d48806";
  return "#595959";
};

export const healthLabel = (h: string, t: TFunction): string => {
  if (h === "healthy") return t("cluster.healthy");
  if (h === "suspect") return t("cluster.suspect");
  return t("cluster.dead");
};

export const healthColor = (h: string): string => {
  if (h === "healthy") return "#52c41a";
  if (h === "suspect") return "#faad14";
  return "#f5222d";
};

export const healthDot = (h: string): string => healthColor(h);

export const formatAge = (ms: number, t: TFunction): string => {
  const age = Date.now() - ms;
  if (age < 1000) return `${age}${t("cluster.msAgo") ?? "ms"}`;
  return `${(age / 1000).toFixed(1)}s ago`;
};
