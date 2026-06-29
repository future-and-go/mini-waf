import { Card, Table, Typography, Button, Space, Tag } from "antd";
import { CheckCircleOutlined, LinkOutlined } from "@ant-design/icons";
import type { ColumnsType } from "antd/es/table";
import { useGo } from "@refinedev/core";
import { useTranslation } from "react-i18next";

import { GOVERNANCE_MAP, type GovernanceEntry } from "../../utils/governance-map";
import { useEnforcementCapabilities } from "../../hooks/use-enforcement-capabilities";

const yes = <CheckCircleOutlined style={{ color: "#52c41a" }} />;
const dash = <Typography.Text type="secondary">—</Typography.Text>;

// S6 — read-only governance matrix. Teaches operators where each capability is
// actually governed so a mode toggle with "no effect" is understood, not a bug.
export const PlaneMap: React.FC = () => {
  const { t } = useTranslation();
  const go = useGo();
  const { result } = useEnforcementCapabilities();
  const caps = result?.data;

  // Control plane is driven by the live capabilities snapshot, not a static
  // assumption. effective mode = per-feature override, else the default.
  const controlPlaneCell = (feature: string) => {
    if (!caps) {
      return <Tag>{t("enforcement.controlUnknown", { defaultValue: "unknown" })}</Tag>;
    }
    const cap = caps.features[feature];
    if (!cap) {
      return <Tag>{t("enforcement.controlReference", { defaultValue: "reference" })}</Tag>;
    }
    const mode = caps.active.overrides[feature] ?? caps.active.default_mode;
    if (cap.supported && mode === "enforce") return yes;
    return <Tag>{t("enforcement.controlOff", { defaultValue: "off" })}</Tag>;
  };

  const columns: ColumnsType<GovernanceEntry> = [
    {
      title: t("enforcement.colCapability"),
      dataIndex: "feature",
      render: (feature: string) => <strong>{feature}</strong>,
    },
    {
      title: t("enforcement.colConfigPlane"),
      width: 160,
      align: "center",
      render: (_, row) => (row.config ? yes : dash),
    },
    {
      title: t("enforcement.colAdminPlane"),
      width: 200,
      align: "center",
      render: (_, row) =>
        row.adminPath ? (
          <Space size={4}>
            {yes}
            <Button
              type="link"
              size="small"
              icon={<LinkOutlined />}
              onClick={() => go({ to: row.adminPath as string })}
            >
              {t("enforcement.open")}
            </Button>
          </Space>
        ) : (
          dash
        ),
    },
    {
      title: t("enforcement.colControlPlane"),
      width: 140,
      align: "center",
      render: (_, row) => controlPlaneCell(row.feature),
    },
  ];

  return (
    <Card title={t("enforcement.planeMapTitle")}>
      <Table<GovernanceEntry>
        rowKey="feature"
        size="small"
        dataSource={GOVERNANCE_MAP}
        columns={columns}
        pagination={false}
      />
      <Typography.Paragraph type="secondary" style={{ marginTop: 12, marginBottom: 0 }}>
        {t("enforcement.planeMapFooter")}
      </Typography.Paragraph>
    </Card>
  );
};
