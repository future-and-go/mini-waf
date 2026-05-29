import { Space, Typography, Button, Tooltip } from "antd";
import { ReloadOutlined, SaveOutlined } from "@ant-design/icons";
import type { TFunction } from "i18next";

interface PageHeaderProps {
  loading: boolean;
  saving: boolean;
  disabled: boolean;
  isAdmin: boolean;
  rbacTooltip: string;
  onRefresh: () => void;
  onSave: () => void;
  t: TFunction;
}

export const PageHeader: React.FC<PageHeaderProps> = ({
  loading,
  saving,
  disabled,
  isAdmin,
  rbacTooltip,
  onRefresh,
  onSave,
  t,
}) => (
  <Space style={{ width: "100%", justifyContent: "space-between" }}>
    <div>
      <Typography.Title level={4} style={{ margin: 0 }}>
        {t("tierPolicies.title")}
      </Typography.Title>
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        {t("tierPolicies.subtitle")}
      </Typography.Text>
    </div>
    <Space>
      <Button
        icon={<ReloadOutlined spin={loading} />}
        onClick={onRefresh}
        disabled={disabled}
      >
        {t("common.refresh")}
      </Button>
      <Tooltip title={rbacTooltip}>
        <Button
          type="primary"
          icon={<SaveOutlined />}
          loading={saving}
          onClick={onSave}
          disabled={disabled || !isAdmin}
        >
          {t("common.save")}
        </Button>
      </Tooltip>
    </Space>
  </Space>
);
