import { useEffect, useMemo, useRef, useState } from "react";
import {
  Row,
  Col,
  Card,
  Button,
  Tag,
  Space,
  Table,
  Typography,
  theme,
  Statistic,
  Alert,
  Empty,
} from "antd";
import {
  ReloadOutlined,
  ThunderboltOutlined,
  StopOutlined,
  CheckCircleOutlined,
  PercentageOutlined,
  CloudServerOutlined,
  TeamOutlined,
  BookOutlined,
  AppstoreOutlined,
  GlobalOutlined,
  AlertOutlined,
  EnvironmentOutlined,
  WifiOutlined,
  ExclamationCircleOutlined,
  BugOutlined,
} from "@ant-design/icons";
import { useCustom } from "@refinedev/core";
import { useTranslation } from "react-i18next";
import { tokenStorage } from "../../utils/axios";
import type { ColumnsType } from "antd/es/table";
import { KpiCard } from "../../components/kpi-card";
import { TopList } from "../../components/top-list";
import { CategoryBars, categoryColors, actionColors } from "../../components/category-bars";
import { RiskBandPreview } from "../../components/risk-band-preview";
import { TrafficChart } from "../../components/traffic-chart";
import { EngineBadge } from "../../components/engine-badge";
import { EndpointHeatmap } from "../../components/endpoint-heatmap";
import { DashboardFilters } from "../../components/dashboard-filters";
import type { RecentEvent, StatsOverview, TopEntry, TrafficPoint, EndpointHeatmap as EndpointHeatmapData } from "../../types/api";
import { fmtNum, fmtPct, fmtTime } from "../../utils/format";

const ENGINES = [
  { name: "libinjection", description: "SQLi & XSS fingerprint", enabled: true },
  { name: "OWASP CRS", description: "Core Rule Set (YAML)", enabled: true },
  { name: "Rhai Scripts", description: "Custom rule engine", enabled: true },
  { name: "Bot Detection", description: "UA + behaviour heuristics", enabled: true },
  { name: "Scanner", description: "Nikto / Acunetix / ZAP", enabled: true },
  { name: "CC / DDoS", description: "Token-bucket per IP", enabled: true },
  { name: "SSRF Guard", description: "URL + DNS rebinding pin", enabled: true },
  { name: "Path Traversal", description: "LFI / RFI detection", enabled: true },
  { name: "Command Inject", description: "Shell / exec patterns", enabled: true },
  { name: "Sensitive Data", description: "Aho-Corasick PII leak", enabled: true },
  { name: "Anti-Hotlink", description: "Referer validation", enabled: true },
  { name: "GeoIP", description: "Country allow/deny list", enabled: true },
  { name: "WASM Plugins", description: "wasmtime sandbox", enabled: true },
  { name: "ModSecurity", description: "SecRule directives", enabled: true },
];

interface RuleRegistry {
  enabled?: number;
  disabled?: number;
  rules?: { category?: string }[];
}

interface PanelConfigData {
  config?: {
    risk_allow?: number;
    risk_challenge?: number;
    risk_block?: number;
  };
}

// ISO 3166-1 alpha-2 code → emoji flag
function getFlagEmoji(iso: string): string {
  if (!iso || iso.length !== 2) return "🌍";
  return iso
    .toUpperCase()
    .split("")
    .map((c) => String.fromCodePoint(127397 + c.charCodeAt(0)))
    .join("");
}

export const DashboardPage: React.FC = () => {
  const { t } = useTranslation();
  const { token } = theme.useToken();

  const [filterHostCode, setFilterHostCode] = useState("");
  const [filterAction, setFilterAction] = useState("");
  const [filterHours, setFilterHours] = useState(24);

  // Hot data: stats refresh every 5s; traffic timeseries every 30s; rule
  // registry once on mount (changes rarely). Each query has its own cache key.
  const overview = useCustom<StatsOverview>({
    url: "/api/stats/overview",
    method: "get",
    config: {
      query: {
        host_code: filterHostCode || undefined,
        action: filterAction || undefined,
        hours: filterHours !== 24 ? filterHours : undefined,
      },
    },
    queryOptions: {
      staleTime: 5_000,
      refetchInterval: 5_000,
      queryKey: ["stats-overview", filterHostCode, filterAction, filterHours],
    },
  });

  const timeseries = useCustom<TrafficPoint[]>({
    url: "/api/stats/timeseries",
    method: "get",
    config: { query: { hours: 24 } },
    queryOptions: { staleTime: 30_000, refetchInterval: 30_000 },
  });

  const registry = useCustom<RuleRegistry>({
    url: "/api/rules/registry",
    method: "get",
    queryOptions: { staleTime: 5 * 60_000 },
  });

  const hostsQuery = useCustom<{ data: Array<{ host_code: string; host: string }> }>({
    url: "/api/hosts",
    method: "get",
    queryOptions: { staleTime: 5 * 60_000 },
  });

  const panelConfig = useCustom<PanelConfigData>({
    url: "/api/panel-config",
    method: "get",
    queryOptions: { staleTime: 60_000, retry: false },
  });
  const panelCfg = panelConfig.result?.data?.config;

  const heatmap = useCustom<EndpointHeatmapData>({
    url: "/api/stats/endpoints",
    method: "get",
    config: {
      query: {
        hours: filterHours,
        host_code: filterHostCode || undefined,
        action: filterAction || undefined,
      },
    },
    queryOptions: {
      staleTime: 10_000,
      refetchInterval: 30_000,
      queryKey: ["stats-endpoints", filterHostCode, filterAction, filterHours],
    },
  });

  const stats = overview.result?.data;
  const traffic = timeseries.result?.data ?? [];
  const reg = registry.result?.data;

  const challengeCount = stats?.action_breakdown?.find((e) => e.key === "challenge")?.count ?? 0;
  const honeypotCount = stats?.action_breakdown?.find((e) => e.key === "honeypot")?.count ?? 0;
  const challengeRate =
    stats?.total_requests && stats.total_requests > 0
      ? ((challengeCount / stats.total_requests) * 100).toFixed(1)
      : "0.0";

  const countriesWithFlags = useMemo(
    () =>
      (stats?.top_countries ?? []).map((e) => ({
        ...e,
        key: `${getFlagEmoji(e.key)} ${e.key}`,
      })),
    [stats?.top_countries],
  );

  const riskIpData = useMemo(
    () => (stats?.top_ips ?? []).map((e, i) => ({ ...e, rank: i + 1 })),
    [stats?.top_ips],
  );

  const ruleStats = useMemo(() => {
    const total = (reg?.enabled ?? 0) + (reg?.disabled ?? 0);
    const cats = new Set((reg?.rules ?? []).map((r) => r.category).filter(Boolean));
    return { total, categories: cats.size };
  }, [reg]);

  // Live WebSocket feed for the bottom panel. Independent of liveProvider
  // because that one is invalidate-on-message; here we just show the raw
  // stream of events for operator inspection.
  const [liveEvents, setLiveEvents] = useState<unknown[]>([]);
  const [wsConnected, setWsConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    const tk = tokenStorage.get();
    if (!tk) return;
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/ws/events`, [`bearer.${tk}`]);
    wsRef.current = ws;
    ws.onopen = () => setWsConnected(true);
    ws.onclose = () => setWsConnected(false);
    ws.onerror = () => setWsConnected(false);
    ws.onmessage = (ev) => {
      try {
        const payload = JSON.parse(ev.data);
        setLiveEvents((prev) => [payload, ...prev].slice(0, 50));
      } catch {
        // ignore malformed frames
      }
    };
    return () => {
      ws.close();
      wsRef.current = null;
    };
  }, []);

  const refreshAll = () => {
    overview.query.refetch();
    timeseries.query.refetch();
    registry.query.refetch();
    heatmap.query.refetch();
    panelConfig.query.refetch();
  };

  const riskIpColumns: ColumnsType<TopEntry & { rank: number }> = [
    {
      title: t("dashboard.rankNum"),
      dataIndex: "rank",
      width: 60,
      render: (v: number) => (
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          #{v}
        </Typography.Text>
      ),
    },
    {
      title: t("dashboard.topIPs"),
      dataIndex: "key",
      render: (v: string) => (
        <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>{v}</span>
      ),
    },
    {
      title: t("common.total"),
      dataIndex: "count",
      width: 100,
      render: (v: number) => fmtNum(v),
    },
    {
      title: t("dashboard.ipStatus"),
      width: 110,
      render: (_: unknown, row: TopEntry & { rank: number }) => {
        if (row.count > 10) return <Tag color="red">{t("dashboard.ipHighRisk")}</Tag>;
        if (row.count > 3) return <Tag color="orange">{t("dashboard.ipActive")}</Tag>;
        return <Tag color="gold">{t("dashboard.ipMonitoring")}</Tag>;
      },
    },
  ];

  const recentColumns: ColumnsType<RecentEvent> = [
    {
      title: t("dashboard.time"),
      dataIndex: "ts",
      width: 110,
      render: (v: string) => <span style={{ color: "#8c8c8c", fontSize: 12 }}>{fmtTime(v)}</span>,
    },
    {
      title: t("dashboard.clientIp"),
      dataIndex: "client_ip",
      width: 140,
      render: (v: string) => <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>{v}</span>,
    },
    { title: t("dashboard.country"), dataIndex: "country", width: 90, render: (v?: string) => v ?? "—" },
    {
      title: t("dashboard.method"),
      dataIndex: "method",
      width: 80,
      render: (v: string) => <Tag color="default">{v}</Tag>,
    },
    {
      title: t("dashboard.path"),
      dataIndex: "path",
      ellipsis: true,
      render: (v: string) => (
        <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }} title={v}>
          {v}
        </span>
      ),
    },
    { title: t("dashboard.rule"), dataIndex: "rule_id", width: 120, render: (v?: string) => v ?? "—" },
    {
      title: t("dashboard.category"),
      dataIndex: "category",
      width: 130,
      render: (v: string) => (
        <Tag color={categoryColors[v] ?? "default"} style={{ color: "#fff" }}>
          {v}
        </Tag>
      ),
    },
    {
      title: t("dashboard.action"),
      dataIndex: "action",
      width: 90,
      render: (v: string) => (
        <Tag color={actionColors[v] ?? "default"} style={{ color: "#fff" }}>
          {v}
        </Tag>
      ),
    },
  ];

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Row justify="space-between" align="middle">
        <Col>
          <Typography.Title level={3} style={{ margin: 0 }}>
            {t("dashboard.title")}
          </Typography.Title>
          <Typography.Text type="secondary">{t("dashboard.subtitle")}</Typography.Text>
        </Col>
        <Col>
          <Space>
            <Tag color={wsConnected ? "success" : "default"}>
              {wsConnected ? t("dashboard.live") : t("dashboard.disconnected")}
            </Tag>
            <Button
              icon={<ReloadOutlined spin={overview.query.isFetching} />}
              onClick={refreshAll}
              loading={overview.query.isFetching}
            >
              {t("dashboard.refresh")}
            </Button>
          </Space>
        </Col>
      </Row>

      <DashboardFilters
        hostCode={filterHostCode}
        action={filterAction}
        hours={filterHours}
        hosts={hostsQuery.result?.data?.data ?? []}
        onChange={({ hostCode, action, hours }) => {
          setFilterHostCode(hostCode);
          setFilterAction(action);
          setFilterHours(hours);
        }}
        loading={hostsQuery.query.isLoading}
      />

      <Row gutter={[12, 12]}>
        <Col xs={12} lg={6}>
          <KpiCard label={t("dashboard.totalRequests")} value={fmtNum(stats?.total_requests)} icon={ThunderboltOutlined} color="blue" loading={overview.query.isLoading} />
        </Col>
        <Col xs={12} lg={6}>
          <KpiCard label={t("dashboard.blockedRequests")} value={fmtNum(stats?.total_blocked)} icon={StopOutlined} color="red" loading={overview.query.isLoading} />
        </Col>
        <Col xs={12} lg={6}>
          <KpiCard label={t("dashboard.allowedRequests")} value={fmtNum(stats?.total_allowed)} icon={CheckCircleOutlined} color="green" loading={overview.query.isLoading} />
        </Col>
        <Col xs={12} lg={6}>
          <KpiCard label={t("dashboard.blockRate")} value={fmtPct(stats?.block_rate)} icon={PercentageOutlined} color="orange" loading={overview.query.isLoading} />
        </Col>
      </Row>

      <Row gutter={[12, 12]}>
        <Col xs={12} lg={6}>
          <KpiCard label={t("dashboard.activeHosts")} value={fmtNum(stats?.hosts_count)} icon={CloudServerOutlined} color="purple" />
        </Col>
        <Col xs={12} lg={6}>
          <KpiCard label={t("dashboard.uniqueAttackers")} value={fmtNum(stats?.unique_attackers)} icon={TeamOutlined} color="rose" />
        </Col>
        <Col xs={12} lg={6}>
          <KpiCard label={t("dashboard.rulesLoaded")} value={fmtNum(ruleStats.total)} icon={BookOutlined} color="indigo" />
        </Col>
        <Col xs={12} lg={6}>
          <KpiCard label={t("dashboard.categories")} value={fmtNum(ruleStats.categories)} icon={AppstoreOutlined} color="teal" />
        </Col>
      </Row>

      {/* Challenged + Honeypot KPI row */}
      <Row gutter={[12, 12]}>
        <Col xs={12} lg={6}>
          <Card size="small" style={{ height: "100%" }}>
            <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between" }}>
              <div>
                <Statistic
                  title={t("dashboard.challenged")}
                  value={fmtNum(challengeCount)}
                  loading={overview.query.isLoading}
                  valueStyle={{ fontSize: 22, fontWeight: 600 }}
                />
                <Tag color="orange" style={{ marginTop: 4, fontSize: 11 }}>
                  {challengeRate}% {t("dashboard.challenge_rate")}
                </Tag>
              </div>
              <div
                style={{
                  width: 36, height: 36, borderRadius: 8,
                  background: "#fa8c161a", display: "flex",
                  alignItems: "center", justifyContent: "center", flexShrink: 0,
                }}
              >
                <ExclamationCircleOutlined style={{ color: "#fa8c16", fontSize: 18 }} />
              </div>
            </div>
          </Card>
        </Col>
        <Col xs={12} lg={6}>
          <KpiCard
            label={t("dashboard.honeypotHits")}
            value={fmtNum(honeypotCount)}
            icon={BugOutlined}
            color="purple"
            loading={overview.query.isLoading}
          />
        </Col>
      </Row>

      <Card
        size="small"
        title={t("dashboard.trafficChart")}
        extra={
          <Space size="middle" style={{ fontSize: 12 }}>
            <Space size={4}>
              <span style={{ width: 10, height: 10, background: "#1677ff", borderRadius: 2, display: "inline-block" }} />
              {t("dashboard.legitTraffic")}
            </Space>
            <Space size={4}>
              <span style={{ width: 10, height: 10, background: "#f5222d", borderRadius: 2, display: "inline-block" }} />
              {t("dashboard.blockedTraffic")}
            </Space>
          </Space>
        }
      >
        <TrafficChart series={traffic} />
      </Card>

      <Row gutter={[12, 12]}>
        <Col xs={24} lg={12}>
          <Card size="small" title={t("dashboard.categoryBreakdown")}>
            <CategoryBars items={stats?.category_breakdown} colors={categoryColors} />
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card size="small" title={t("dashboard.actionBreakdown")}>
            <CategoryBars items={stats?.action_breakdown} colors={actionColors} />
          </Card>
        </Col>
      </Row>

      {/* Risk Score Distribution */}
      {!panelConfig.query.isError && (
        <Card
          size="small"
          title={t("dashboard.riskDistribution")}
          loading={panelConfig.query.isLoading && !panelCfg}
        >
          {panelCfg ? (
            <Row gutter={[16, 16]} align="middle">
              <Col xs={24} lg={14}>
                <RiskBandPreview
                  riskAllow={panelCfg.risk_allow ?? 50}
                  riskChallenge={panelCfg.risk_challenge ?? 74}
                  riskBlock={panelCfg.risk_block ?? 75}
                />
              </Col>
              <Col xs={24} lg={10}>
                <Row gutter={[8, 0]}>
                  <Col span={8}>
                    <Statistic
                      title={t("security.allowed")}
                      value={stats?.action_breakdown?.find((e) => e.key === "allow")?.count ?? 0}
                      valueStyle={{ color: "#52c41a", fontSize: 18 }}
                      loading={overview.query.isLoading}
                    />
                  </Col>
                  <Col span={8}>
                    <Statistic
                      title={t("dashboard.challenged")}
                      value={challengeCount}
                      valueStyle={{ color: "#fa8c16", fontSize: 18 }}
                      loading={overview.query.isLoading}
                    />
                  </Col>
                  <Col span={8}>
                    <Statistic
                      title={t("security.blocked")}
                      value={stats?.action_breakdown?.find((e) => e.key === "block")?.count ?? 0}
                      valueStyle={{ color: "#f5222d", fontSize: 18 }}
                      loading={overview.query.isLoading}
                    />
                  </Col>
                </Row>
              </Col>
            </Row>
          ) : (
            <Alert
              type="info"
              showIcon
              message={t("settings.panel.notConfigured")}
            />
          )}
        </Card>
      )}

      <Card size="small" title={t("dashboard.endpointHeatmap")}>
        <EndpointHeatmap
          data={heatmap.result?.data}
          loading={heatmap.query.isLoading}
        />
      </Card>

      <Row gutter={[12, 12]}>
        <Col xs={24} lg={12}>
          <TopList title={t("dashboard.topCountries")} items={countriesWithFlags} icon={EnvironmentOutlined} badgeColor="#722ed1" />
        </Col>
        <Col xs={24} lg={12}>
          <TopList title={t("dashboard.topIsps")} items={stats?.top_isps} icon={WifiOutlined} badgeColor="#1677ff" />
        </Col>
      </Row>

      <Row gutter={[12, 12]}>
        <Col xs={24} lg={12}>
          <TopList title={t("dashboard.topIPs")} items={stats?.top_ips} icon={GlobalOutlined} badgeColor="#cf1322" mono />
        </Col>
        <Col xs={24} lg={12}>
          <TopList title={t("dashboard.topRules")} items={stats?.top_rules} icon={AlertOutlined} badgeColor="#fa8c16" />
        </Col>
      </Row>

      {/* Top IPs by Risk table */}
      <Card size="small" title={t("dashboard.topIpsByRisk")}>
        <Table<TopEntry & { rank: number }>
          rowKey="key"
          size="small"
          dataSource={riskIpData}
          columns={riskIpColumns}
          loading={overview.query.isLoading}
          pagination={false}
          locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} /> }}
          scroll={{ x: 400 }}
        />
      </Card>

      <Card size="small" title={t("dashboard.detectionEngines")}>
        <Row gutter={[8, 8]}>
          {ENGINES.map((eng) => (
            <Col key={eng.name} xs={12} sm={8} lg={6} xl={4}>
              <EngineBadge name={eng.name} description={eng.description} enabled={eng.enabled} />
            </Col>
          ))}
        </Row>
      </Card>

      <Card size="small" title={t("dashboard.recentEvents")}>
        <Table
          rowKey={(r, i) => `${r.ts}-${i}`}
          size="small"
          dataSource={Array.isArray(stats?.recent_events) ? stats.recent_events : []}
          columns={recentColumns}
          pagination={false}
          locale={{ emptyText: t("dashboard.noRecentEvents") }}
          scroll={{ x: 900 }}
        />
      </Card>

      <Card size="small" title={t("dashboard.liveEvents")}>
        <div
          style={{
            maxHeight: 240,
            overflowY: "auto",
            display: "flex",
            flexDirection: "column",
            gap: 4,
            background: token.colorBgLayout,
            padding: 8,
            borderRadius: 4,
          }}
        >
          {liveEvents.length === 0 ? (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {t("dashboard.waitingEvents")}
            </Typography.Text>
          ) : (
            liveEvents.map((ev, i) => (
              <code
                key={i}
                style={{
                  fontSize: 11,
                  padding: "2px 6px",
                  background: token.colorBgContainer,
                  borderRadius: 3,
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
              >
                {JSON.stringify(ev)}
              </code>
            ))
          )}
        </div>
      </Card>
    </Space>
  );
};
