import { Card, Descriptions, Space, Button, Alert, Typography, Tag, App, Popconfirm } from "antd";
import { ArrowLeftOutlined, WarningOutlined } from "@ant-design/icons";
import { useCustom, useCustomMutation } from "@refinedev/core";
import { useNavigate, useParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import type { ClusterNode } from "../../types/api";
import { roleLabel, roleColor, healthLabel, healthColor, formatAge } from "./cluster-helpers";

export const ClusterNodeDetailPage: React.FC = () => {
  const { t } = useTranslation();
  const { id = "" } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { message } = App.useApp();

  const { result, query } = useCustom<ClusterNode>({
    url: `/api/cluster/nodes/${id}`,
    method: "get",
    queryOptions: { staleTime: 5_000, refetchInterval: 10_000, enabled: !!id },
  });

  const { mutate: removeNode } = useCustomMutation();

  const node = result?.data;
  const isLoading = query.isLoading;
  const errStatus = (query.error as { statusCode?: number } | null)?.statusCode;
  const errMsg = (query.error as { message?: string } | null)?.message ?? "";
  const disabled = errStatus === 404 && errMsg.includes("cluster not enabled");
  const notFound = errStatus === 404 && !disabled;

  const onRemove = () =>
    removeNode(
      { url: "/api/cluster/nodes/remove", method: "post", values: { node_id: id } },
      {
        onSuccess: () => navigate("/cluster"),
        onError: (err) => message.error(err.message),
      },
    );

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Space>
        <Button type="text" icon={<ArrowLeftOutlined />} onClick={() => navigate("/cluster")} />
        <Typography.Title level={4} style={{ margin: 0 }}>
          {t("cluster.nodeDetail")}
        </Typography.Title>
      </Space>

      {disabled && <Alert type="warning" icon={<WarningOutlined />} showIcon message={t("cluster.clusterDisabled")} />}
      {notFound && <Alert type="error" message={t("common.noData")} showIcon />}
      {isLoading && !node && !disabled && !notFound && <Typography.Text type="secondary">{t("common.loading")}</Typography.Text>}

      {node && (
        <Card
          size="small"
          title={
            <Space>
              <span style={{ display: "inline-block", width: 12, height: 12, background: healthColor(node.health), borderRadius: "50%" }} />
              <span style={{ fontFamily: "ui-monospace, monospace" }}>{node.node_id}</span>
              {node.is_self && <Tag color="blue">{t("cluster.isSelf")}</Tag>}
            </Space>
          }
          extra={
            !node.is_self && (
              <Popconfirm title={t("cluster.confirmRemove")} onConfirm={onRemove}>
                <Button danger>{t("cluster.removeNode")}</Button>
              </Popconfirm>
            )
          }
        >
          <Descriptions column={{ xs: 1, sm: 2, md: 3 }} size="small">
            <Descriptions.Item label={t("cluster.role")}>
              <span style={{ color: roleColor(node.role), fontWeight: 500 }}>{roleLabel(node.role, t)}</span>
            </Descriptions.Item>
            <Descriptions.Item label={t("cluster.health")}>
              <span style={{ color: healthColor(node.health), fontWeight: 500 }}>{healthLabel(node.health, t)}</span>
            </Descriptions.Item>
            <Descriptions.Item label={t("cluster.term")}>{node.term}</Descriptions.Item>
            <Descriptions.Item label={t("cluster.addr")}>
              <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>{node.addr ?? "—"}</span>
            </Descriptions.Item>
            <Descriptions.Item label={t("cluster.rulesVersion")}>{node.rules_version}</Descriptions.Item>
            <Descriptions.Item label={t("cluster.configVersion")}>{node.config_version}</Descriptions.Item>
            {node.last_seen_ms && (
              <Descriptions.Item label={t("cluster.lastSeen")}>{formatAge(node.last_seen_ms, t)}</Descriptions.Item>
            )}
          </Descriptions>
        </Card>
      )}
    </Space>
  );
};
