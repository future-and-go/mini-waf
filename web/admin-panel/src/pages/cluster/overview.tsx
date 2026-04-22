import { Card, Row, Col, Statistic, Space, Button, Typography, Alert, List, Tag } from "antd";
import { ReloadOutlined, WarningOutlined } from "@ant-design/icons";
import { useCustom } from "@refinedev/core";
import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";
import type { ClusterStatus } from "../../types/api";
import { roleLabel, roleColor, healthLabel, healthColor, formatAge } from "./cluster-helpers";

export const ClusterOverviewPage: React.FC = () => {
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

  if (disabled) {
    return <Alert type="warning" icon={<WarningOutlined />} showIcon message={t("cluster.clusterDisabled")} />;
  }

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <Typography.Title level={4} style={{ margin: 0 }}>
          {t("cluster.overview")}
        </Typography.Title>
        <Button icon={<ReloadOutlined spin={isFetching} />} onClick={() => refetch()}>
          {t("common.refresh")}
        </Button>
      </Space>

      {isLoading ? (
        <Typography.Text type="secondary">{t("cluster.loading")}</Typography.Text>
      ) : status ? (
        <>
          <Row gutter={[12, 12]}>
            <Col xs={12} md={6}><Card size="small"><Statistic title={t("cluster.totalNodes")} value={status.total_nodes} valueStyle={{ color: "#1677ff" }} /></Card></Col>
            <Col xs={12} md={6}><Card size="small"><Statistic title={t("cluster.role")} value={roleLabel(status.role, t)} valueStyle={{ color: roleColor(status.role) }} /></Card></Col>
            <Col xs={12} md={6}><Card size="small"><Statistic title={t("cluster.term")} value={status.term} valueStyle={{ color: "#722ed1" }} /></Card></Col>
            <Col xs={12} md={6}><Card size="small"><Statistic title={t("cluster.rulesVersion")} value={status.rules_version} /></Card></Col>
          </Row>

          <Card
            size="small"
            title={t("cluster.nodeId") + "s"}
            extra={<Typography.Text type="secondary" style={{ fontSize: 12 }}>{status.listen_addr}</Typography.Text>}
          >
            <List
              dataSource={Array.isArray(status.nodes) ? status.nodes : []}
              locale={{ emptyText: t("cluster.noNodes") }}
              renderItem={(node) => (
                <List.Item
                  actions={[
                    <span key="role" style={{ color: roleColor(node.role), fontWeight: 500 }}>{roleLabel(node.role, t)}</span>,
                    <span key="health" style={{ color: healthColor(node.health), fontWeight: 500 }}>{healthLabel(node.health, t)}</span>,
                    node.last_seen_ms ? <span key="last" style={{ fontSize: 11, fontFamily: "ui-monospace, monospace", color: "#8c8c8c" }}>{formatAge(node.last_seen_ms, t)}</span> : null,
                    <Link key="d" to={`/cluster/nodes/${node.node_id}`}>{t("common.actions")} →</Link>,
                  ].filter(Boolean) as React.ReactNode[]}
                >
                  <List.Item.Meta
                    avatar={<span style={{ display: "inline-block", width: 10, height: 10, background: healthColor(node.health), borderRadius: "50%" }} />}
                    title={
                      <Space>
                        <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 13 }}>{node.node_id}</span>
                        {node.is_self && <Tag color="blue">{t("cluster.selfLabel")}</Tag>}
                      </Space>
                    }
                    description={node.addr ?? "—"}
                  />
                </List.Item>
              )}
            />
          </Card>
        </>
      ) : null}
    </Space>
  );
};
