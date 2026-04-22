import { Card, Descriptions, Button, Space, Typography, Tag, App } from "antd";
import { ReloadOutlined, ThunderboltOutlined } from "@ant-design/icons";
import { useCustom, useCustomMutation } from "@refinedev/core";
import { useTranslation } from "react-i18next";
import type { SystemStatus } from "../../types/api";

export const SettingsPage: React.FC = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();

  const { result, query } = useCustom<SystemStatus>({
    url: "/api/status",
    method: "get",
    queryOptions: { staleTime: 5_000, refetchInterval: 10_000 },
  });

  const { mutate: reload, mutation: reloadMutation } = useCustomMutation();

  const status = result?.data;
  const isLoading = query.isLoading;
  const reloading = reloadMutation.isPending;
  const refetch = query.refetch;

  const onReload = () => {
    reload(
      { url: "/api/reload", method: "post", values: {} },
      {
        onSuccess: () => {
          message.success(t("settings.rulesReloaded"));
          refetch();
        },
        onError: (err) => message.error(err.message),
      },
    );
  };

  const ipsCount = (status?.rules?.allow_ips ?? 0) + (status?.rules?.block_ips ?? 0);
  const urlsCount = (status?.rules?.allow_urls ?? 0) + (status?.rules?.block_urls ?? 0);

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Typography.Title level={4}>{t("settings.title")}</Typography.Title>

      <Card
        title={t("settings.systemStatus")}
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={() => refetch()} loading={isLoading}>
              {t("common.refresh")}
            </Button>
            <Button type="primary" icon={<ThunderboltOutlined />} onClick={onReload} loading={reloading}>
              {t("settings.reloadRules")}
            </Button>
          </Space>
        }
        loading={isLoading && !status}
      >
        <Descriptions column={{ xs: 1, sm: 2, lg: 4 }} size="small">
          <Descriptions.Item label={t("settings.version")}>
            <Tag color="blue">{status?.version ?? "—"}</Tag>
          </Descriptions.Item>
          <Descriptions.Item label={t("settings.activeHosts")}>{status?.hosts ?? 0}</Descriptions.Item>
          <Descriptions.Item label={t("settings.totalRequests")}>
            {status?.total_requests?.toLocaleString() ?? 0}
          </Descriptions.Item>
          <Descriptions.Item label={t("settings.rules")}>
            IPs: {ipsCount} / URLs: {urlsCount}
          </Descriptions.Item>
        </Descriptions>
      </Card>

      <Card title={t("settings.configuration")}>
        <Space direction="vertical" size={6} style={{ width: "100%" }}>
          <Typography.Text type="secondary">
            API endpoint: <Typography.Text code>http://&lt;host&gt;:9527</Typography.Text>
          </Typography.Text>
          <Typography.Text type="secondary">
            Admin UI: <Typography.Text code>http://&lt;host&gt;:9527/ui/</Typography.Text>
          </Typography.Text>
          <Typography.Text type="secondary">
            WebSocket events: <Typography.Text code>ws://&lt;host&gt;:9527/ws/events</Typography.Text> (protocol:
            bearer.JWT)
          </Typography.Text>
          <Typography.Text type="secondary">
            WebSocket logs: <Typography.Text code>ws://&lt;host&gt;:9527/ws/logs</Typography.Text> (protocol:
            bearer.JWT)
          </Typography.Text>
          <Typography.Paragraph type="secondary" style={{ marginTop: 12, marginBottom: 0, fontSize: 12 }}>
            Set <Typography.Text code>JWT_SECRET</Typography.Text> and{" "}
            <Typography.Text code>MASTER_KEY</Typography.Text> environment variables for production security.
          </Typography.Paragraph>
        </Space>
      </Card>
    </Space>
  );
};
