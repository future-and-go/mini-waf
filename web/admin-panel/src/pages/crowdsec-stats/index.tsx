import { Card, Row, Col, Statistic, Space, Button, Typography, Empty, Tag, Alert } from "antd";
import { ReloadOutlined } from "@ant-design/icons";
import { useCustom } from "@refinedev/core";
import { useTranslation } from "react-i18next";
import { useMemo, useState, useEffect } from "react";

interface CrowdsecStats {
  total_decisions?: number;
  by_type?: Record<string, number>;
  by_scenario?: Record<string, number>;
  cache?: { hits: number; misses: number; hit_rate_pct: number };
}

const typeColor = (t_: string): string =>
  ({ ban: "red", captcha: "gold", throttle: "orange" }[t_] ?? "default");

export const CrowdsecStatsPage: React.FC = () => {
  const { t } = useTranslation();
  const [lastRefresh, setLastRefresh] = useState("—");

  const { result, query } = useCustom<CrowdsecStats>({
    url: "/api/crowdsec/stats",
    method: "get",
    queryOptions: { staleTime: 5_000, refetchInterval: 10_000 },
  });
  const refetch = query.refetch;
  const isLoading = query.isLoading;
  const isFetching = query.isFetching;
  const dataUpdatedAt = query.dataUpdatedAt;

  useEffect(() => {
    if (dataUpdatedAt) setLastRefresh(new Date(dataUpdatedAt).toLocaleTimeString());
  }, [dataUpdatedAt]);

  const stats = result?.data;

  const maxTypeCount = useMemo(() => {
    if (!stats?.by_type) return 1;
    return Math.max(...Object.values(stats.by_type), 1);
  }, [stats]);

  const topScenarios = useMemo(() => {
    if (!stats?.by_scenario) return [];
    return Object.entries(stats.by_scenario)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);
  }, [stats]);

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <Typography.Title level={4} style={{ margin: 0 }}>
          {t("crowdsec.statsTitle")}
        </Typography.Title>
        <Button icon={<ReloadOutlined spin={isFetching} />} onClick={() => refetch()} type="primary">
          {t("common.refresh")}
        </Button>
      </Space>

      {!stats?.total_decisions && !isLoading && (
        <Alert type="warning" message={t("crowdsec.notActive")} showIcon />
      )}

      <Row gutter={[12, 12]}>
        <Col xs={24} md={8}>
          <Card size="small">
            <Statistic title={t("crowdsec.cachedDecisions")} value={stats?.total_decisions ?? 0} valueStyle={{ color: "#1677ff" }} />
          </Card>
        </Col>
        <Col xs={24} md={8}>
          <Card size="small">
            <Statistic title={t("crowdsec.cacheHits")} value={stats?.cache?.hits ?? 0} valueStyle={{ color: "#52c41a" }} />
          </Card>
        </Col>
        <Col xs={24} md={8}>
          <Card size="small">
            <Statistic title={t("crowdsec.cacheHitRate")} value={stats?.cache?.hit_rate_pct ?? 0} precision={1} suffix="%" valueStyle={{ color: "#722ed1" }} />
          </Card>
        </Col>
      </Row>

      <Row gutter={[12, 12]}>
        <Col xs={24} md={12}>
          <Card size="small" title={t("crowdsec.byType")}>
            {!stats?.by_type || Object.keys(stats.by_type).length === 0 ? (
              <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t("common.noData")} />
            ) : (
              <Space direction="vertical" size={6} style={{ width: "100%" }}>
                {Object.entries(stats.by_type).map(([type, count]) => (
                  <div key={type} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <Tag color={typeColor(type)} style={{ width: 80, textAlign: "center", marginRight: 0 }}>{type}</Tag>
                    <div style={{ flex: 1, height: 8, background: "#f0f0f0", borderRadius: 4, overflow: "hidden" }}>
                      <div style={{ width: `${(count / maxTypeCount) * 100}%`, height: "100%", background: "#1677ff" }} />
                    </div>
                    <span style={{ width: 50, textAlign: "right", fontSize: 13 }}>{count}</span>
                  </div>
                ))}
              </Space>
            )}
          </Card>
        </Col>
        <Col xs={24} md={12}>
          <Card size="small" title={t("crowdsec.topScenarios")}>
            {topScenarios.length === 0 ? (
              <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t("common.noData")} />
            ) : (
              <Space direction="vertical" size={4} style={{ width: "100%" }}>
                {topScenarios.map(([scenario, count]) => (
                  <div key={scenario} style={{ display: "flex", justifyContent: "space-between", fontSize: 13 }}>
                    <Typography.Text ellipsis style={{ maxWidth: 280 }} title={scenario}>{scenario}</Typography.Text>
                    <Typography.Text type="secondary">{count}</Typography.Text>
                  </div>
                ))}
              </Space>
            )}
          </Card>
        </Col>
      </Row>

      <Card size="small">
        <Space style={{ width: "100%", justifyContent: "space-between" }}>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {stats?.total_decisions != null
              ? `${t("crowdsec.syncActive")} — ${stats.total_decisions} ${t("crowdsec.decisionsInCache")} (${stats.cache?.hits ?? 0} ${t("crowdsec.hits")} / ${stats.cache?.misses ?? 0} ${t("crowdsec.misses")})`
              : t("crowdsec.syncNotRunning")}
          </Typography.Text>
          <Typography.Text type="secondary" style={{ fontSize: 11 }}>
            {t("crowdsec.lastRefresh")} {lastRefresh}
          </Typography.Text>
        </Space>
      </Card>
    </Space>
  );
};
