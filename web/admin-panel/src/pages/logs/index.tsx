import { useMemo, useState } from "react";
import {
  Card,
  Col,
  Row,
  Space,
  Switch,
  Typography,
  Button,
  Statistic,
  message,
} from "antd";
import { ReloadOutlined } from "@ant-design/icons";
import { useList, useCustom } from "@refinedev/core";

import {
  LogsFilters,
  defaultLogsFilters,
  filtersToCrud,
  type LogsFilterState,
} from "./LogsFilters";
import { LogsTable, type LogRow } from "./LogsTable";
import type { SecurityEvent, StatsOverview } from "../../types/api";

// ─── Boundary mapper ─────────────────────────────────────────────────────────
// Parse-first: the one typed place that adapts a `/api/security-events` row to
// the free-form `LogRow` the table renders. `event_type` is derived from the
// enforcement `action` (no dedicated column exists); `host_code`→`host`. Extra
// fields (`waf_mode`, `country`) ride along as discoverable columns.
const toLogRow = (e: SecurityEvent): LogRow => ({
  _time: e.created_at,
  event_type: e.action,
  rule_name: e.rule_name,
  rule_id: e.rule_id ?? null,
  client_ip: e.client_ip,
  host: e.host_code,
  method: e.method,
  path: e.path,
  detail: e.detail ?? undefined,
  req_id: e.id,
  waf_mode: e.waf_mode,
  tier: e.tier ?? undefined,
  country: e.geo_info?.country ?? e.country,
});

// ─── Page ────────────────────────────────────────────────────────────────────

export const LogsPage: React.FC = () => {
  const [filters, setFilters] = useState<LogsFilterState>(defaultLogsFilters);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [refreshInterval, setRefreshInterval] = useState<number>(0);
  const [pageSize, setPageSize] = useState<number>(100);
  const [currentPage, setCurrentPage] = useState<number>(1);

  const filterArray = useMemo(() => filtersToCrud(filters), [filters]);

  // Any filter change (tier/range/action selects apply immediately; text inputs
  // bubble on Apply) must return to page 1 — otherwise a smaller filtered set can
  // leave the pager on an out-of-range page showing an empty table.
  const handleFiltersChange = (next: LogsFilterState) => {
    setFilters(next);
    setCurrentPage(1);
  };

  const { result, query } = useList<SecurityEvent>({
    resource: "security-events",
    filters: filterArray,
    pagination: { currentPage, pageSize, mode: "server" },
    queryOptions: {
      staleTime: 0,
      refetchInterval: autoRefresh && refreshInterval > 0 ? refreshInterval : false,
    },
  });

  // "Entries (24h)" — real count from the same overview the dashboard KPI uses.
  const overview = useCustom<StatsOverview>({
    url: "/api/stats/overview",
    method: "get",
    config: { query: { hours: 24 } },
  });
  const total24h = overview.query.data?.data?.total_requests ?? null;

  const total = result?.total ?? 0;

  // Decorate rows with stable keys (timestamp + req_id) so AntD doesn't fall
  // back to row-index keys (which break expansion across re-renders).
  const rows = useMemo(() => {
    const list = Array.isArray(result?.data) ? result.data : [];
    return list.map((e, idx) => {
      const row = toLogRow(e);
      return { ...row, __rowKey: `${row._time ?? ""}-${row.req_id ?? ""}-${idx}` };
    });
  }, [result?.data]);

  const handleRun = () => {
    setCurrentPage(1);
    void query.refetch();
    void overview.query.refetch();
  };

  const handleFilterClientIp = (ip: string) => {
    setFilters((s) => ({ ...s, clientIp: ip }));
    setCurrentPage(1);
    void message.info(`Filter set: client_ip = ${ip}`);
  };

  const handleFilterRuleName = (rule: string) => {
    setFilters((s) => ({ ...s, ruleName: rule }));
    setCurrentPage(1);
    void message.info(`Filter set: rule_name = ${rule}`);
  };

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <Typography.Title level={4} style={{ margin: 0 }}>
          Security Logs
        </Typography.Title>
        <Space>
          <Switch
            checkedChildren="Auto"
            unCheckedChildren="Manual"
            checked={autoRefresh}
            onChange={setAutoRefresh}
          />
          {autoRefresh && (
            <Space.Compact>
              <Button
                size="small"
                type={refreshInterval === 10_000 ? "primary" : "default"}
                onClick={() => setRefreshInterval(10_000)}
              >
                10s
              </Button>
              <Button
                size="small"
                type={refreshInterval === 30_000 ? "primary" : "default"}
                onClick={() => setRefreshInterval(30_000)}
              >
                30s
              </Button>
              <Button
                size="small"
                type={refreshInterval === 60_000 ? "primary" : "default"}
                onClick={() => setRefreshInterval(60_000)}
              >
                60s
              </Button>
            </Space.Compact>
          )}
          <Button icon={<ReloadOutlined spin={query.isFetching} />} onClick={handleRun}>
            Refresh
          </Button>
        </Space>
      </Space>

      <Row gutter={12}>
        <Col span={6}>
          <Card size="small">
            <Statistic
              title="Entries (24h)"
              value={total24h ?? "—"}
              valueStyle={{ fontSize: 18 }}
              loading={overview.query.isLoading}
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={12}>
        <Col span={6}>
          <LogsFilters
            value={filters}
            onChange={handleFiltersChange}
            onApply={handleRun}
            loading={query.isFetching}
          />
        </Col>
        <Col span={18}>
          <Card size="small">
            <LogsTable
              rows={rows}
              loading={query.isFetching}
              pageSize={pageSize}
              setPageSize={setPageSize}
              total={total}
              currentPage={currentPage}
              onPageChange={setCurrentPage}
              onFilterClientIp={handleFilterClientIp}
              onFilterRuleName={handleFilterRuleName}
            />
          </Card>
        </Col>
      </Row>
    </Space>
  );
};
