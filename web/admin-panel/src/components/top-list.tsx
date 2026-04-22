import { Card, Empty, Tag, Typography } from "antd";
import type { ComponentType } from "react";
import type { TopEntry } from "../types/api";
import { fmtNum } from "../utils/format";

interface TopListProps {
  title: string;
  items: TopEntry[] | undefined;
  icon?: ComponentType<{ style?: React.CSSProperties }>;
  badgeColor?: string;
  mono?: boolean;
}

export const TopList: React.FC<TopListProps> = ({ title, items, icon: Icon, badgeColor = "#fa8c16", mono }) => {
  // Harden against non-array inputs — backend/useCustom wrapping can vary.
  const rows = Array.isArray(items) ? items : [];
  const max = Math.max(...rows.map((i) => Number(i.count) || 0), 1);

  return (
    <Card
      size="small"
      title={
        <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
          {Icon && <Icon style={{ fontSize: 14, color: "#8c8c8c" }} />}
          {title}
        </span>
      }
    >
      {rows.length === 0 ? (
        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No data" />
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {rows.slice(0, 10).map((item) => {
            const pct = (Number(item.count) / max) * 100;
            return (
              <div key={item.key} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <div style={{ flex: 1, position: "relative", height: 24 }}>
                  <div
                    style={{
                      position: "absolute",
                      inset: 0,
                      width: `${pct}%`,
                      background: "rgba(0,0,0,0.04)",
                      borderRadius: 3,
                    }}
                  />
                  <Typography.Text
                    style={{
                      position: "relative",
                      paddingLeft: 8,
                      lineHeight: "24px",
                      fontFamily: mono ? "ui-monospace, monospace" : undefined,
                      fontSize: mono ? 12 : 13,
                    }}
                    ellipsis
                  >
                    {item.key}
                  </Typography.Text>
                </div>
                <Tag color={badgeColor} style={{ marginInlineEnd: 0 }}>
                  {fmtNum(item.count)}
                </Tag>
              </div>
            );
          })}
        </div>
      )}
    </Card>
  );
};
