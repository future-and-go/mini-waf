import { Card } from "antd";
import { CheckCircleFilled, MinusCircleFilled } from "@ant-design/icons";

interface EngineBadgeProps {
  name: string;
  description: string;
  enabled: boolean;
}

export const EngineBadge: React.FC<EngineBadgeProps> = ({ name, description, enabled }) => (
  <Card
    size="small"
    style={{
      borderColor: enabled ? "#b7eb8f" : "#d9d9d9",
      background: enabled ? "#f6ffed" : "#fafafa",
      opacity: enabled ? 1 : 0.6,
    }}
    styles={{ body: { padding: "8px 12px" } }}
  >
    <div style={{ display: "flex", alignItems: "flex-start", gap: 8 }}>
      {enabled ? (
        <CheckCircleFilled style={{ color: "#52c41a", marginTop: 3 }} />
      ) : (
        <MinusCircleFilled style={{ color: "#bfbfbf", marginTop: 3 }} />
      )}
      <div style={{ minWidth: 0 }}>
        <div style={{ fontSize: 12, fontWeight: 600 }}>{name}</div>
        <div
          style={{ fontSize: 11, color: "#8c8c8c", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
          title={description}
        >
          {description}
        </div>
      </div>
    </div>
  </Card>
);
