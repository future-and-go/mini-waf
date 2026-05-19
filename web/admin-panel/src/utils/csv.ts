// CSV export helpers — pure functions, no side-effects except Blob creation.

const escapeCell = (value: unknown): string => {
  const str = value == null ? "" : String(value);
  if (str.includes(",") || str.includes('"') || str.includes("\n")) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
};

export const buildCsvRow = (values: unknown[]): string =>
  values.map(escapeCell).join(",");

export const downloadCsv = (rows: string[], filename: string): void => {
  const content = rows.join("\n");
  const blob = new Blob([content], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
};
