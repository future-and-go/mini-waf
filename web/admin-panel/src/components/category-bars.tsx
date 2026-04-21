import { Empty, Typography } from "antd";
import type { TopEntry } from "../types/api";
import { fmtNum } from "../utils/format";

interface CategoryBarsProps {
  items: TopEntry[] | undefined;
  colors: Record<string, string>;
}

export const CategoryBars: React.FC<CategoryBarsProps> = ({ items, colors }) => {
  const rows = Array.isArray(items) ? items : [];
  const max = Math.max(...rows.map((i) => Number(i.count) || 0), 1);

  if (rows.length === 0) {
    return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No data" />;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {rows.map((item) => {
        const pct = Math.max(4, (Number(item.count) / max) * 100);
        const color = colors[item.key] ?? "#8c8c8c";
        return (
          <div key={item.key} style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <Typography.Text style={{ width: 130, fontSize: 12 }} ellipsis>
              {item.key}
            </Typography.Text>
            <div style={{ flex: 1, height: 20, background: "#f0f0f0", borderRadius: 3, overflow: "hidden" }}>
              <div
                style={{
                  height: "100%",
                  width: `${pct}%`,
                  background: color,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "flex-end",
                  paddingRight: 6,
                  color: "white",
                  fontSize: 11,
                  fontWeight: 500,
                }}
              >
                {fmtNum(item.count)}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
};

// Domain-specific palettes ported from the legacy Vue Dashboard.
export const categoryColors: Record<string, string> = {
  sqli: "#f5222d", xss: "#fa8c16", rce: "#cf1322",
  lfi: "#faad14", rfi: "#d48806",
  "path-traversal": "#faad14",
  "php-injection": "#eb2f96", "nodejs-injection": "#a0d911",
  "protocol-enforcement": "#69c0ff", "protocol-attack": "#1890ff",
  scanner: "#722ed1", bot: "#c41d7f", "cc-ddos": "#fadb14",
  ssrf: "#13c2c2", ssti: "#08979c", advanced: "#2f54eb",
  "owasp-crs": "#1d39c4", "data-leakage": "#52c41a",
  "api-security": "#1677ff", "mass-assignment": "#0958d9",
  "web-shell": "#820014", modsecurity: "#531dab",
  cve: "#5c0011", "geo-blocking": "#9254de",
  custom: "#595959",
  "ip-rule": "#8c8c8c", "url-rule": "#737373",
  "sensitive-data": "#389e0d", "anti-hotlink": "#40a9ff",
  other: "#bfbfbf",
};

export const actionColors: Record<string, string> = {
  block: "#f5222d", log: "#fadb14", allow: "#52c41a",
  challenge: "#fa8c16", redirect: "#1677ff",
};
