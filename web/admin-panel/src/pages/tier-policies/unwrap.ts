// Backend envelope: { success: true, data: <payload> } — unwrap to T or pass-through.
export const unwrap = <T>(raw: unknown): T | undefined =>
  raw && typeof raw === "object" && "data" in (raw as Record<string, unknown>)
    ? (raw as { data?: T }).data
    : (raw as T | undefined);
