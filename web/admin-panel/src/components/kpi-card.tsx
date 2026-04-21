import { Card, Statistic } from "antd";
import type { ComponentType } from "react";

type KpiColor = "blue" | "red" | "green" | "orange" | "purple" | "indigo" | "teal" | "rose";

const colorMap: Record<KpiColor, string> = {
  blue: "#1677ff",
  red: "#f5222d",
  green: "#52c41a",
  orange: "#fa8c16",
  purple: "#722ed1",
  indigo: "#2f54eb",
  teal: "#13c2c2",
  rose: "#eb2f96",
};

interface KpiCardProps {
  label: string;
  value: string | number;
  icon: ComponentType<{ style?: React.CSSProperties }>;
  color?: KpiColor;
  loading?: boolean;
}

export const KpiCard: React.FC<KpiCardProps> = ({ label, value, icon: Icon, color = "blue", loading }) => {
  const accent = colorMap[color];

  return (
    <Card size="small" style={{ height: "100%" }}>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between" }}>
        <Statistic title={label} value={value} loading={loading} valueStyle={{ fontSize: 22, fontWeight: 600 }} />
        <div
          style={{
            width: 36,
            height: 36,
            borderRadius: 8,
            background: `${accent}1a`,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexShrink: 0,
          }}
        >
          <Icon style={{ color: accent, fontSize: 18 }} />
        </div>
      </div>
    </Card>
  );
};
