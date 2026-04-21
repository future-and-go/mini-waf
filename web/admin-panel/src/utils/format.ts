import dayjs from "dayjs";

export const fmtNum = (n: number | undefined | null): string => {
  if (n == null) return "—";
  return new Intl.NumberFormat().format(n);
};

export const fmtPct = (n: number | undefined | null): string => {
  if (n == null) return "—";
  return `${(n * 100).toFixed(2)}%`;
};

export const fmtTime = (iso: string | number | undefined | null): string => {
  if (iso == null) return "—";
  const d = dayjs(iso);
  return d.isValid() ? d.format("HH:mm:ss") : String(iso);
};

export const fmtDateTime = (iso: string | number | undefined | null): string => {
  if (iso == null) return "—";
  const d = dayjs(iso);
  return d.isValid() ? d.format("YYYY-MM-DD HH:mm:ss") : String(iso);
};

export const fmtAge = (ms: number): string => {
  const age = Date.now() - ms;
  if (age < 1000) return `${age}ms ago`;
  if (age < 60_000) return `${(age / 1000).toFixed(1)}s ago`;
  if (age < 3_600_000) return `${Math.floor(age / 60_000)}m ago`;
  return `${Math.floor(age / 3_600_000)}h ago`;
};
