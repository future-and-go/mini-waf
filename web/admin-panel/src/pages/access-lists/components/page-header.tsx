import { Space, Typography, Switch, Tag, Button, Tooltip } from "antd";
import { ReloadOutlined, SaveOutlined } from "@ant-design/icons";
import type { TFunction } from "i18next";

interface PageHeaderProps {
  version: number;
  dryRun: boolean;
  saving: boolean;
  fetching: boolean;
  isAdmin: boolean;
  rbacTooltip: string;
  onDryRunChange: (v: boolean) => void;
  onRefresh: () => void;
  onSave: () => void;
  t: TFunction;
}

export const PageHeader: React.FC<PageHeaderProps> = ({
  version,
  dryRun,
  saving,
  fetching,
  isAdmin,
  rbacTooltip,
  onDryRunChange,
  onRefresh,
  onSave,
  t,
}) => (
  <Space style={{ width: "100%", justifyContent: "space-between" }}>
    <div>
      <Typography.Title level={4} style={{ margin: 0 }}>
        {t("accessLists.title")}
      </Typography.Title>
      <Space size="small" style={{ marginTop: 4 }}>
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          {t("accessLists.version")}: v{version}
        </Typography.Text>
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>·</Typography.Text>
        <Space size={4}>
          <Switch size="small" checked={dryRun} disabled={!isAdmin} onChange={onDryRunChange} />
          <Typography.Text style={{ fontSize: 12 }}>{t("accessLists.dryRun")}</Typography.Text>
          {dryRun && (
            <Tag color="orange" style={{ fontSize: 11 }}>
              {t("accessLists.dryRunActive")}
            </Tag>
          )}
        </Space>
      </Space>
    </div>
    <Space>
      <Button icon={<ReloadOutlined spin={fetching} />} onClick={onRefresh}>
        {t("common.refresh")}
      </Button>
      <Tooltip title={rbacTooltip}>
        <Button
          type="primary"
          icon={<SaveOutlined />}
          loading={saving}
          onClick={onSave}
          disabled={!isAdmin}
        >
          {t("common.save")}
        </Button>
      </Tooltip>
    </Space>
  </Space>
);
