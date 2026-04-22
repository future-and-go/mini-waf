import { Card, Space, Button, Table, Typography, Alert, Tag } from "antd";
import { ReloadOutlined, WarningOutlined } from "@ant-design/icons";
import { useCustom } from "@refinedev/core";
import type { ColumnsType } from "antd/es/table";
import { useTranslation } from "react-i18next";
import { useMemo } from "react";
import type { ClusterNode, ClusterStatus } from "../../types/api";
import { roleLabel, roleColor, healthLabel, healthColor } from "./cluster-helpers";

export const ClusterSyncPage: React.FC = () => {
  const { t } = useTranslation();

  const { result, query } = useCustom<ClusterStatus>({
    url: "/api/cluster/status",
    method: "get",
    queryOptions: { staleTime: 5_000, refetchInterval: 5_000 },
  });
  const refetch = query.refetch;
  const isLoading = query.isLoading;
  const isFetching = query.isFetching;

  const status = result?.data;
  const disabled = (query.error as { statusCode?: number } | null)?.statusCode === 404;

  const hasDrift = useMemo(() => {
    if (!status || !Array.isArray(status.nodes)) return false;
    const master = status.rules_version;
    return status.nodes.some((n) => !n.is_self && n.rules_version !== 0 && n.rules_version !== master);
  }, [status]);

  const columns: ColumnsType<ClusterNode> = [
    {
      title: t("cluster.nodeId"),
      dataIndex: "node_id",
      render: (v: string, r) => (
        <Space>
          <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>{v}</span>
          {r.is_self && <Tag color="blue">{t("cluster.isSelf")}</Tag>}
        </Space>
      ),
    },
    {
      title: t("cluster.role"),
      dataIndex: "role",
      width: 100,
      render: (v: string) => <span style={{ color: roleColor(v), fontWeight: 500 }}>{roleLabel(v, t)}</span>,
    },
    { title: t("cluster.rulesVersion"), dataIndex: "rules_version", width: 130, render: (v) => <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>{v}</span> },
    { title: t("cluster.configVersion"), dataIndex: "config_version", width: 140, render: (v) => <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>{v}</span> },
    {
      title: t("cluster.syncDrift"),
      key: "drift",
      width: 110,
      render: (_v, r) => {
        if (!status || r.is_self || r.rules_version === 0) return null;
        const delta = status.rules_version - r.rules_version;
        return delta !== 0 ? (
          <Typography.Text type="warning" style={{ fontSize: 12 }}>Δ {delta}</Typography.Text>
        ) : (
          <Typography.Text type="success" style={{ fontSize: 12 }}>{t("cluster.syncInSync")}</Typography.Text>
        );
      },
    },
    {
      title: t("cluster.health"),
      dataIndex: "health",
      width: 100,
      render: (v: string) => <span style={{ color: healthColor(v), fontWeight: 500 }}>{healthLabel(v, t)}</span>,
    },
  ];

  if (disabled) {
    return <Alert type="warning" icon={<WarningOutlined />} showIcon message={t("cluster.syncNoCluster")} />;
  }

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <div>
          <Typography.Title level={4} style={{ margin: 0 }}>
            {t("cluster.syncTitle")}
          </Typography.Title>
          <Typography.Text type="secondary">{t("cluster.syncSubtitle")}</Typography.Text>
        </div>
        <Button icon={<ReloadOutlined spin={isFetching} />} onClick={() => refetch()}>
          {t("common.refresh")}
        </Button>
      </Space>

      {hasDrift && <Alert type="warning" icon={<WarningOutlined />} showIcon message={t("cluster.syncDriftAlert")} />}

      <Card size="small">
        <Table
          rowKey="node_id"
          size="small"
          dataSource={Array.isArray(status?.nodes) ? status.nodes : []}
          columns={columns}
          loading={isLoading}
          pagination={false}
          locale={{ emptyText: t("cluster.noNodes") }}
        />
      </Card>

      {status && (
        <Typography.Text type="secondary" style={{ fontSize: 11 }}>
          Master rules version: <Typography.Text code>{status.rules_version}</Typography.Text> · Config version:{" "}
          <Typography.Text code>{status.config_version}</Typography.Text> · Term:{" "}
          <Typography.Text code>{status.term}</Typography.Text>
        </Typography.Text>
      )}
    </Space>
  );
};
