import { useMemo, useState } from "react";
import {
  Row, Col, Card, Button, Space, Typography, Table, Tag,
  Input, Select, Switch, Drawer, Descriptions, Empty, Tooltip,
} from "antd";
import {
  ReloadOutlined, DownloadOutlined, ClearOutlined, InfoCircleOutlined,
  ArrowRightOutlined, SearchOutlined, FilterOutlined,
} from "@ant-design/icons";
import { useCustom, useTable } from "@refinedev/core";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";
import dayjs from "dayjs";
import type { ColumnsType } from "antd/es/table";

import { Line } from "@ant-design/plots";

import type { StatsOverview, TrafficPoint, SecurityEvent, TopEntry } from "../../types/api";
import { categoryColors, actionColors } from "../../components/category-bars";
import { TopList } from "../../components/top-list";
import { TrafficChart } from "../../components/traffic-chart";
import { DonutCard } from "../../components/analytics/donut-card";
import { UriTiles } from "../../components/analytics/uri-tiles";
import { TimeRangeSegmented } from "../../components/analytics/time-range-segmented";
import { fmtDateTime } from "../../utils/format";
import { buildCsvRow, downloadCsv } from "../../utils/csv";

interface CategoryPoint {
  ts: string;
  category: string;
  count: number;
}

type Hours = 1 | 6 | 24 | 168;

interface AnalyticsFilters {
  hostCode?: string;
  timeRange: Hours;
  category?: string;
  action?: string;
  ruleId?: string;
  searchPath?: string;
  // Rules Details table search fields
  searchRuleId?: string;
  searchRuleName?: string;
  searchAction?: string;
  searchClientIp?: string;
  searchCountry?: string;
}

// ── Quick-view drawer ─────────────────────────────────────────────────────────

interface QuickDrawerProps {
  event: SecurityEvent | null;
  onClose: () => void;
  onOpenFull: (id: string) => void;
}

const QuickDrawer: React.FC<QuickDrawerProps> = ({ event, onClose, onOpenFull }) => {
  const { t } = useTranslation();
  const geo = event?.geo_info;

  return (
    <Drawer
      open={!!event}
      onClose={onClose}
      width={480}
      title={
        <Space>
          <InfoCircleOutlined />
          <span>{t("analytics.rulesDetails")}</span>
        </Space>
      }
      footer={
        event && (
          <Button
            type="primary"
            icon={<ArrowRightOutlined />}
            onClick={() => onOpenFull(event.id)}
          >
            {t("eventDetail.title")} →
          </Button>
        )
      }
      destroyOnClose
    >
      {event && (
        <Descriptions column={1} size="small" bordered>
          <Descriptions.Item label={t("security.ruleId")}>
            <Typography.Text code>{event.rule_id ?? "—"}</Typography.Text>
          </Descriptions.Item>
          <Descriptions.Item label={t("security.ruleName")}>{event.rule_name}</Descriptions.Item>
          <Descriptions.Item label={t("security.clientIP")}>
            <Typography.Text code>{event.client_ip}</Typography.Text>
          </Descriptions.Item>
          <Descriptions.Item label={t("security.country")}>
            {geo?.country ?? "—"}
          </Descriptions.Item>
          <Descriptions.Item label={t("security.path")}>
            <Typography.Text code style={{ wordBreak: "break-all", fontSize: 11 }}>
              {event.path}
            </Typography.Text>
          </Descriptions.Item>
          <Descriptions.Item label={t("security.method")}>
            <Tag>{event.method}</Tag>
          </Descriptions.Item>
          <Descriptions.Item label={t("security.action")}>
            <Tag color={actionColors[event.action] ?? "default"} style={{ color: "#fff" }}>
              {event.action}
            </Tag>
          </Descriptions.Item>
          <Descriptions.Item label={t("security.detail")}>
            <Typography.Text
              style={{ fontSize: 11, whiteSpace: "pre-wrap", wordBreak: "break-all" }}
            >
              {event.detail ?? "—"}
            </Typography.Text>
          </Descriptions.Item>
          <Descriptions.Item label={t("security.time")}>
            {fmtDateTime(event.created_at)}
          </Descriptions.Item>
        </Descriptions>
      )}
    </Drawer>
  );
};

// ── Main page ─────────────────────────────────────────────────────────────────

export const RuleAnalyticsPage: React.FC = () => {
  const { t } = useTranslation();
  const navigate = useNavigate();

  const [filters, setFilters] = useState<AnalyticsFilters>({ timeRange: 24 });
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [quickEvent, setQuickEvent] = useState<SecurityEvent | null>(null);

  const hasActiveFilters = !!(
    filters.category || filters.action || filters.ruleId || filters.searchPath ||
    filters.searchRuleId || filters.searchRuleName || filters.searchAction ||
    filters.searchClientIp || filters.searchCountry
  );

  const hasTableFilters = !!(
    filters.searchRuleId || filters.searchRuleName || filters.searchAction ||
    filters.searchClientIp || filters.searchCountry
  );

  // ── Stats overview (10s) ─────────────────────────────────────────────────
  const overview = useCustom<StatsOverview>({
    url: "/api/stats/overview",
    method: "get",
    queryOptions: {
      staleTime: 10_000,
      refetchInterval: 10_000,
      queryKey: ["analytics-overview"],
    },
  });

  // ── Timeseries (60s) — total/blocked fallback ─────────────────────────────
  const timeseries = useCustom<TrafficPoint[]>({
    url: "/api/stats/timeseries",
    method: "get",
    config: { query: { hours: filters.timeRange } },
    queryOptions: {
      staleTime: 60_000,
      refetchInterval: 60_000,
      queryKey: ["analytics-timeseries", filters.timeRange],
    },
  });

  // ── Per-category stacked timeline (60s) ─────────────────────────────────
  const categoryTimeseries = useCustom<CategoryPoint[]>({
    url: "/api/stats/timeseries-by-category",
    method: "get",
    config: {
      query: {
        hours: filters.timeRange,
        host_code: filters.hostCode || undefined,
      },
    },
    queryOptions: {
      staleTime: 60_000,
      refetchInterval: 60_000,
      queryKey: ["analytics-timeseries-by-category", filters.timeRange, filters.hostCode],
    },
  });

  // ── Hosts list ───────────────────────────────────────────────────────────
  const hostsQuery = useCustom<{ data: Array<{ host_code: string; host: string }> }>({
    url: "/api/hosts",
    method: "get",
    queryOptions: { staleTime: 5 * 60_000 },
  });

  // ── Blocked events (client-side URI grouping) ────────────────────────────
  const blockedEvents = useCustom<{ data: SecurityEvent[]; total: number }>({
    url: "/api/security-events",
    method: "get",
    config: {
      query: {
        action: "block",
        page: 1,
        page_size: 100,
        host_code: filters.hostCode || undefined,
      },
    },
    queryOptions: {
      staleTime: 30_000,
      refetchInterval: 30_000,
      queryKey: ["analytics-blocked-uris", filters.hostCode],
    },
  });

  // ── Full log table (server-side pagination, 10s) ─────────────────────────
  const {
    tableQuery,
    result: tableResult,
    currentPage,
    setCurrentPage,
    pageSize,
    setPageSize,
    setFilters: setTableFilters,
  } = useTable<SecurityEvent>({
    resource: "security-events",
    pagination: { currentPage: 1, pageSize: 25, mode: "server" },
    filters: {
      // Ensure host_code filter is applied from initial state on first mount.
      initial: [
        { field: "host_code", operator: "eq", value: filters.hostCode || undefined },
      ],
    },
    queryOptions: {
      staleTime: 0,
      refetchInterval: autoRefresh ? 10_000 : false,
    },
  });

  // Apply compound filter to table whenever analytics filter changes.
  // Table search fields (searchRuleId, etc.) take precedence over the
  // chart-driven filters (ruleId, action) when both are set simultaneously.
  const applyTableFilters = (f: AnalyticsFilters) => {
    setTableFilters(
      [
        { field: "host_code",  operator: "eq",       value: f.hostCode          || undefined },
        { field: "action",     operator: "eq",       value: f.searchAction || f.action || undefined },
        { field: "rule_id",    operator: "eq",       value: f.searchRuleId || f.ruleId || undefined },
        { field: "path",       operator: "contains", value: f.searchPath        || undefined },
        { field: "rule_name",  operator: "eq",       value: f.searchRuleName    || undefined },
        { field: "client_ip",  operator: "eq",       value: f.searchClientIp    || undefined },
        { field: "country",    operator: "contains", value: f.searchCountry     || undefined },
      ],
      "replace",
    );
    setCurrentPage(1);
  };

  const updateFilter = (patch: Partial<AnalyticsFilters>) => {
    const next = { ...filters, ...patch };
    setFilters(next);
    applyTableFilters(next);
  };

  const clearFilters = () => {
    const next: AnalyticsFilters = { timeRange: filters.timeRange, hostCode: filters.hostCode };
    setFilters(next);
    applyTableFilters(next);
  };

  // ── URI tiles ────────────────────────────────────────────────────────────
  const uriTiles = useMemo(() => {
    const raw = blockedEvents.result?.data;
    const events: SecurityEvent[] = Array.isArray(raw)
      ? raw
      : Array.isArray((raw as unknown as { data: SecurityEvent[] })?.data)
      ? (raw as unknown as { data: SecurityEvent[] }).data
      : [];

    const byPath = new Map<string, number>();
    for (const ev of events) byPath.set(ev.path, (byPath.get(ev.path) ?? 0) + 1);
    return [...byPath.entries()]
      .map(([path, count]) => ({ path, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 30);
  }, [blockedEvents.result]);

  const stats = overview.result?.data;
  const traffic = timeseries.result?.data ?? [];
  const categoryPoints: CategoryPoint[] = (() => {
    const raw = categoryTimeseries.result?.data;
    return Array.isArray(raw) ? raw : [];
  })();
  const tableData = Array.isArray(tableResult?.data) ? tableResult.data : [];
  const tableTotal = tableResult?.total ?? 0;

  // ── Export CSV ───────────────────────────────────────────────────────────
  const handleExportCsv = () => {
    const header = buildCsvRow([
      "created_at", "host_code", "client_ip", "method", "path",
      "rule_id", "rule_name", "action", "country",
    ]);
    const rows = tableData.map((ev) =>
      buildCsvRow([
        ev.created_at, ev.host_code, ev.client_ip, ev.method, ev.path,
        ev.rule_id ?? "", ev.rule_name, ev.action,
        ev.geo_info?.country ?? "",
      ]),
    );
    downloadCsv([header, ...rows], `security-events-${dayjs().format("YYYYMMDD-HHmm")}.csv`);
  };

  const refreshAll = () => {
    overview.query.refetch();
    timeseries.query.refetch();
    categoryTimeseries.query.refetch();
    blockedEvents.query.refetch();
    tableQuery.refetch();
  };

  // ── Table columns ────────────────────────────────────────────────────────
  const columns: ColumnsType<SecurityEvent> = [
    {
      title: t("security.time"),
      dataIndex: "created_at",
      width: 165,
      render: (v: string) => (
        <span style={{ color: "#8c8c8c", fontSize: 12 }}>{fmtDateTime(v)}</span>
      ),
    },
    {
      title: t("security.ruleId"),
      dataIndex: "rule_id",
      width: 130,
      render: (v: string | null) =>
        v ? (
          <Typography.Text
            code
            style={{ fontSize: 11, cursor: "pointer" }}
            onClick={(e) => {
              e.stopPropagation();
              updateFilter({ ruleId: v });
            }}
          >
            {v}
          </Typography.Text>
        ) : (
          <span style={{ color: "#bfbfbf" }}>—</span>
        ),
    },
    {
      title: t("security.action"),
      dataIndex: "action",
      width: 90,
      render: (v: string) => (
        <Tag
          color={actionColors[v] ?? "default"}
          style={{ color: "#fff" }}
        >
          {v}
        </Tag>
      ),
    },
    {
      title: t("security.ruleName"),
      dataIndex: "rule_name",
      width: 180,
      ellipsis: true,
    },
    {
      title: t("security.path"),
      dataIndex: "path",
      ellipsis: true,
      render: (v: string) => (
        <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 11 }} title={v}>
          {v}
        </span>
      ),
    },
    {
      title: t("security.clientIP"),
      dataIndex: "client_ip",
      width: 135,
      render: (v: string) => (
        <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>{v}</span>
      ),
    },
    {
      title: t("security.hostCode"),
      dataIndex: "host_code",
      width: 110,
      ellipsis: true,
    },
    {
      title: t("security.country"),
      width: 90,
      render: (_: unknown, r: SecurityEvent) => r.geo_info?.country ?? "—",
    },
  ];

  // ── TopList wrapper for top_rules: needs onItemClick ─────────────────────
  const topRulesItems: TopEntry[] = stats?.top_rules ?? [];

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      {/* Header */}
      <Row justify="space-between" align="middle" wrap>
        <Col>
          <Typography.Title level={3} style={{ margin: 0 }}>
            {t("analytics.title")}
          </Typography.Title>
          <Typography.Text type="secondary">{t("analytics.subtitle")}</Typography.Text>
        </Col>
        <Col>
          <Space wrap>
            <TimeRangeSegmented
              value={filters.timeRange}
              onChange={(v) => updateFilter({ timeRange: v })}
            />
            <Select
              placeholder={t("analytics.filterByHost")}
              value={filters.hostCode || undefined}
              onChange={(v) => updateFilter({ hostCode: v })}
              allowClear
              style={{ width: 160 }}
              options={(hostsQuery.result?.data?.data ?? []).map((h) => ({
                value: h.host_code,
                label: h.host,
              }))}
              loading={hostsQuery.query.isLoading}
            />
            <Button
              icon={<ClearOutlined />}
              disabled={!hasActiveFilters}
              onClick={clearFilters}
            >
              {t("analytics.clearFilters")}
            </Button>
            <Button
              icon={<DownloadOutlined />}
              onClick={handleExportCsv}
              disabled={tableData.length === 0}
            >
              {t("analytics.exportCsv")}
            </Button>
            <Button
              icon={<ReloadOutlined spin={overview.query.isFetching} />}
              onClick={refreshAll}
            >
              {t("dashboard.refresh")}
            </Button>
          </Space>
        </Col>
      </Row>

      {/* Donut charts */}
      <Row gutter={[12, 12]}>
        <Col xs={24} lg={12}>
          <DonutCard
            title={t("analytics.byRuleGroup")}
            data={stats?.category_breakdown}
            colors={categoryColors}
            onSliceClick={(k) => updateFilter({ category: k })}
            activeKey={filters.category}
            loading={overview.query.isLoading}
          />
        </Col>
        <Col xs={24} lg={12}>
          <DonutCard
            title={t("analytics.byAction")}
            data={stats?.action_breakdown}
            colors={actionColors}
            onSliceClick={(k) => updateFilter({ action: k })}
            activeKey={filters.action}
            loading={overview.query.isLoading}
          />
        </Col>
      </Row>

      {/* Top Blocked URIs */}
      <Card
        size="small"
        title={t("analytics.topBlockedUris")}
        extra={
          <Space>
            <Input
              size="small"
              placeholder={t("analytics.topUrisHint")}
              value={filters.searchPath ?? ""}
              onChange={(e) => updateFilter({ searchPath: e.target.value || undefined })}
              style={{ width: 260 }}
              allowClear
            />
          </Space>
        }
      >
        {uriTiles.length === 0 ? (
          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t("analytics.noEvents")} />
        ) : (
          <UriTiles
            items={uriTiles}
            onSelect={(p) => updateFilter({ searchPath: p })}
            activePath={filters.searchPath}
          />
        )}
      </Card>

      {/* Top Rules + Timeline */}
      <Row gutter={[12, 12]}>
        <Col xs={24} lg={12}>
          <TopList
            title={t("analytics.rulesDetailsSummary")}
            items={topRulesItems}
            badgeColor="#fa8c16"
          />
        </Col>
        <Col xs={24} lg={12}>
          <Card
            size="small"
            title={t("analytics.timeline24h")}
          >
            {categoryPoints.length > 0 ? (
              <Line
                data={categoryPoints.map((p) => ({
                  ts: dayjs(p.ts).format(filters.timeRange <= 24 ? "HH:mm" : "MM-DD HH:mm"),
                  value: p.count,
                  series: p.category,
                }))}
                xField="ts"
                yField="value"
                seriesField="series"
                height={220}
                smooth={false}
                animate={false}
                legend={{ position: "bottom" }}
                color={({ series }: { series: string }) => categoryColors[series] ?? "#8c8c8c"}
                xAxis={{ tickCount: 6 }}
              />
            ) : (
              <TrafficChart series={traffic} />
            )}
          </Card>
        </Col>
      </Row>

      {/* Full Rules Details table */}
      <Card
        size="small"
        title={
          <Space size={8}>
            <span>{t("analytics.rulesDetails")}</span>
            {hasTableFilters && (
              <Tag color="blue" style={{ fontSize: 11 }}>
                <FilterOutlined /> {t("analytics.filtered")}
              </Tag>
            )}
          </Space>
        }
        extra={
          <Space>
            <Switch
              checkedChildren="Auto"
              unCheckedChildren="Manual"
              checked={autoRefresh}
              onChange={setAutoRefresh}
              size="small"
            />
            <Button
              size="small"
              icon={<ReloadOutlined spin={tableQuery.isFetching} />}
              onClick={() => tableQuery.refetch()}
            >
              {t("common.refresh")}
            </Button>
          </Space>
        }
      >
        {/* ── Search bar ─────────────────────────────────────────────────── */}
        <Space
          wrap
          size={6}
          style={{
            marginBottom: 10,
            padding: "8px 10px",
            background: "var(--ant-color-fill-quaternary, #fafafa)",
            borderRadius: 6,
            border: "1px solid var(--ant-color-border-secondary, #e8e8e8)",
            width: "100%",
          }}
        >
          <Input
            size="small"
            allowClear
            prefix={<SearchOutlined style={{ color: "#bfbfbf", fontSize: 11 }} />}
            placeholder={t("security.ruleId")}
            value={filters.searchRuleId ?? ""}
            onChange={(e) => updateFilter({ searchRuleId: e.target.value || undefined })}
            style={{ width: 140, fontFamily: "ui-monospace, monospace", fontSize: 12 }}
          />
          <Input
            size="small"
            allowClear
            prefix={<SearchOutlined style={{ color: "#bfbfbf", fontSize: 11 }} />}
            placeholder={t("security.ruleName")}
            value={filters.searchRuleName ?? ""}
            onChange={(e) => updateFilter({ searchRuleName: e.target.value || undefined })}
            style={{ width: 160 }}
          />
          <Select
            size="small"
            allowClear
            placeholder={t("security.action")}
            value={filters.searchAction ?? undefined}
            onChange={(v) => updateFilter({ searchAction: v ?? undefined })}
            style={{ width: 130 }}
            options={[
              { value: "block",     label: "block"     },
              { value: "allow",     label: "allow"     },
              { value: "log",       label: "log"       },
              { value: "challenge", label: "challenge" },
            ]}
            optionRender={(opt) => (
              <Tag
                color={actionColors[opt.value as string] ?? "default"}
                style={{ margin: 0, cursor: "pointer" }}
              >
                {opt.label as string}
              </Tag>
            )}
            labelRender={(props) => (
              <Tag
                color={actionColors[props.value as string] ?? "default"}
                style={{ margin: 0, lineHeight: "20px" }}
              >
                {props.label as string}
              </Tag>
            )}
          />
          <Input
            size="small"
            allowClear
            prefix={<SearchOutlined style={{ color: "#bfbfbf", fontSize: 11 }} />}
            placeholder={t("security.clientIP")}
            value={filters.searchClientIp ?? ""}
            onChange={(e) => updateFilter({ searchClientIp: e.target.value || undefined })}
            style={{ width: 150, fontFamily: "ui-monospace, monospace", fontSize: 12 }}
          />
          <Input
            size="small"
            allowClear
            prefix={<SearchOutlined style={{ color: "#bfbfbf", fontSize: 11 }} />}
            placeholder={t("security.country")}
            value={filters.searchCountry ?? ""}
            onChange={(e) => updateFilter({ searchCountry: e.target.value || undefined })}
            style={{ width: 110 }}
          />
          {hasTableFilters && (
            <Tooltip title={t("analytics.clearFilters")}>
              <Button
                size="small"
                icon={<ClearOutlined />}
                onClick={() =>
                  updateFilter({
                    searchRuleId: undefined,
                    searchRuleName: undefined,
                    searchAction: undefined,
                    searchClientIp: undefined,
                    searchCountry: undefined,
                  })
                }
              />
            </Tooltip>
          )}
        </Space>

        <Table
          rowKey="id"
          size="small"
          dataSource={tableData}
          columns={columns}
          loading={tableQuery.isLoading}
          pagination={{
            current: currentPage,
            pageSize,
            total: tableTotal,
            onChange: (p, ps) => {
              setCurrentPage(p);
              setPageSize(ps);
            },
            showSizeChanger: true,
            pageSizeOptions: [25, 50, 100],
            showTotal: (n) => `${t("common.total")}: ${n}`,
          }}
          locale={{ emptyText: t("analytics.noEvents") }}
          scroll={{ x: 1000 }}
          onRow={(record) => ({
            style: { cursor: "pointer" },
            onClick: () => setQuickEvent(record),
          })}
        />
      </Card>

      <QuickDrawer
        event={quickEvent}
        onClose={() => setQuickEvent(null)}
        onOpenFull={(id) => {
          setQuickEvent(null);
          navigate(`/security-events/${id}`);
        }}
      />
    </Space>
  );
};
