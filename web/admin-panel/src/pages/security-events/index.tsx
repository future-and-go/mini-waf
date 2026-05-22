import {
  App,
  Card,
  Table,
  Tag,
  Space,
  Input,
  Select,
  Button,
  Typography,
  Switch,
  Drawer,
  Descriptions,
  Badge,
  Divider,
  Skeleton,
  Tabs,
} from "antd";
import { ReloadOutlined, InfoCircleOutlined, PlusOutlined } from "@ant-design/icons";
import { useTable, useOne } from "@refinedev/core";
import type { ColumnsType } from "antd/es/table";
import { useTranslation } from "react-i18next";
import { useState, useEffect, useRef, useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import type { SecurityEvent } from "../../types/api";
import { fmtDateTime } from "../../utils/format";
import { CreateRuleFromEventModal } from "./CreateRuleFromEventModal";

// ── Helpers ────────────────────────────────────────────────────────────────────

function actionColor(action: string): string {
  if (action === "block") return "red";
  if (action === "allow") return "green";
  return "default";
}

function methodColor(method: string): string {
  const map: Record<string, string> = {
    GET: "blue",
    POST: "green",
    PUT: "orange",
    DELETE: "red",
    PATCH: "purple",
  };
  return map[method?.toUpperCase()] ?? "default";
}

// ── Detail Drawer ──────────────────────────────────────────────────────────────

interface EventDetailDrawerProps {
  eventId: string | null;
  onClose: () => void;
  onCreateRule: (event: SecurityEvent) => void;
}

const EventDetailDrawer: React.FC<EventDetailDrawerProps> = ({ eventId, onClose, onCreateRule }) => {
  const { t } = useTranslation();

  const { query } = useOne<SecurityEvent>({
    resource: "security-events",
    id: eventId ?? "",
    queryOptions: { enabled: !!eventId },
  });

  const event = query.data?.data;
  const isLoading = query.isLoading;

  // geo_info may be a JSON object: { country, iso_code, city, region, isp, org, ... }
  const geo = event?.geo_info as Record<string, string> | null | undefined;

  return (
    <Drawer
      title={
        <Space>
          <InfoCircleOutlined />
          <span>{t("security.eventDetail")}</span>
        </Space>
      }
      open={!!eventId}
      onClose={onClose}
      width={600}
      destroyOnClose
    >
      {isLoading ? (
        <Skeleton active paragraph={{ rows: 10 }} />
      ) : event ? (
        <Space direction="vertical" size="middle" style={{ width: "100%" }}>
          {/* ── Request Info ── */}
          <Card size="small" title={t("security.requestInfo")}>
            <Descriptions column={1} size="small" bordered>
              <Descriptions.Item label={t("security.time")}>
                <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 13 }}>
                  {fmtDateTime(event.created_at)}
                </span>
              </Descriptions.Item>
              <Descriptions.Item label={t("security.hostCode")}>
                <Tag>{event.host_code}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label={t("security.clientIP")}>
                <span style={{ fontFamily: "ui-monospace, monospace" }}>{event.client_ip}</span>
              </Descriptions.Item>
              <Descriptions.Item label={t("security.method")}>
                <Tag color={methodColor(event.method)}>{event.method}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label={t("security.path")}>
                <Typography.Text
                  code
                  copyable
                  style={{ wordBreak: "break-all", fontSize: 12 }}
                >
                  {event.path}
                </Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label={t("security.action")}>
                <Badge
                  status={event.action === "block" ? "error" : "success"}
                  text={<Tag color={actionColor(event.action)}>{event.action}</Tag>}
                />
              </Descriptions.Item>
            </Descriptions>
          </Card>

          {/* ── Rule Info ── */}
          <Card size="small" title={t("security.ruleInfo")}>
            <Descriptions column={1} size="small" bordered>
              <Descriptions.Item label={t("security.ruleName")}>
                <strong>{event.rule_name}</strong>
              </Descriptions.Item>
              {event.rule_id && (
                <Descriptions.Item label={t("security.ruleId")}>
                  <Typography.Text code copyable>
                    {event.rule_id}
                  </Typography.Text>
                </Descriptions.Item>
              )}
            </Descriptions>
          </Card>

          {/* ── Geo Location ── */}
          {geo && Object.keys(geo).length > 0 && (
            <Card size="small" title={t("security.geoLocation")}>
              <Descriptions column={1} size="small" bordered>
                {geo.country && (
                  <Descriptions.Item label={t("security.country")}>{geo.country}</Descriptions.Item>
                )}
                {geo.iso_code && (
                  <Descriptions.Item label="ISO">{geo.iso_code}</Descriptions.Item>
                )}
                {geo.city && (
                  <Descriptions.Item label={t("security.city")}>{geo.city}</Descriptions.Item>
                )}
                {geo.region && (
                  <Descriptions.Item label={t("security.region")}>{geo.region}</Descriptions.Item>
                )}
                {geo.isp && (
                  <Descriptions.Item label={t("security.isp")}>{geo.isp}</Descriptions.Item>
                )}
                {geo.org && (
                  <Descriptions.Item label={t("security.org")}>{geo.org}</Descriptions.Item>
                )}
              </Descriptions>
            </Card>
          )}

          {/* ── Attack Payload ── */}
          {event.detail && (
            <Card size="small" title={t("security.attackPayload")}>
              <Typography.Text
                code
                copyable={{ text: event.detail }}
                style={{
                  display: "block",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-all",
                  maxHeight: 300,
                  overflowY: "auto",
                  fontSize: 12,
                }}
              >
                {event.detail}
              </Typography.Text>
            </Card>
          )}

          {!event.detail && (
            <>
              <Divider plain style={{ fontSize: 12, color: "#8c8c8c" }}>
                {t("security.noDetail")}
              </Divider>
            </>
          )}

          <Divider />
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => onCreateRule(event)}
          >
            {t("security.createRuleFromEvent")}
          </Button>
        </Space>
      ) : null}
    </Drawer>
  );
};

// ── Main Page ──────────────────────────────────────────────────────────────────

export const SecurityEventsPage: React.FC = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [searchParams, setSearchParams] = useSearchParams();

  const [hostCode, setHostCode] = useState(searchParams.get("host_code") ?? "");
  const [clientIp, setClientIp] = useState(searchParams.get("client_ip") ?? "");
  const [ruleId, setRuleId] = useState(searchParams.get("rule_id") ?? "");
  const [ruleName, setRuleName] = useState(searchParams.get("rule_name") ?? "");
  const [path, setPath] = useState(searchParams.get("path") ?? "");
  const [action, setAction] = useState<string | undefined>(searchParams.get("action") ?? undefined);
  const [countryFilter, setCountryFilter] = useState<string | undefined>(searchParams.get("country") ?? undefined);
  const [activeTab, setActiveTab] = useState("all");
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [createRuleEvent, setCreateRuleEvent] = useState<SecurityEvent | null>(null);
  // Track last synced URL key to prevent looping when applyFilters also calls setSearchParams.
  const lastSyncedRef = useRef<string>("");

  // Server-side pagination is the only sane default for SecurityEvents:
  // the table can be millions of rows. Filters propagate as `?host_code=...`
  // through the data provider's filter→params flattening.
  const { tableQuery, result, currentPage, setCurrentPage, pageSize, setPageSize, setFilters } = useTable<SecurityEvent>({
    resource: "security-events",
    pagination: { currentPage: 1, pageSize: 20, mode: "server" },
    queryOptions: {
      staleTime: 0,
      refetchInterval: autoRefresh ? 10_000 : false,
    },
  });

  // Sync URL params → filter state whenever search params change (covers both
  // initial mount and same-tab navigation where the component is not re-mounted).
  useEffect(() => {
    const key = searchParams.toString();
    if (key === lastSyncedRef.current) return;
    lastSyncedRef.current = key;

    const urlClientIp = searchParams.get("client_ip");
    const urlRuleId = searchParams.get("rule_id");
    const urlRuleName = searchParams.get("rule_name");
    const urlHostCode = searchParams.get("host_code");
    const urlAction = searchParams.get("action");
    const urlPath = searchParams.get("path");
    const urlCountry = searchParams.get("country");

    if (urlClientIp || urlRuleId || urlRuleName || urlHostCode || urlAction || urlPath || urlCountry !== null) {
      if (urlHostCode !== null) setHostCode(urlHostCode);
      if (urlClientIp !== null) setClientIp(urlClientIp);
      if (urlRuleId !== null) setRuleId(urlRuleId);
      if (urlRuleName !== null) setRuleName(urlRuleName);
      if (urlPath !== null) setPath(urlPath);
      if (urlAction !== null) setAction(urlAction || undefined);
      if (urlCountry !== null) setCountryFilter(urlCountry || undefined);

      setFilters(
        [
          { field: "host_code", operator: "eq", value: urlHostCode || undefined },
          { field: "client_ip", operator: "eq", value: urlClientIp || undefined },
          { field: "rule_id", operator: "eq", value: urlRuleId || undefined },
          { field: "rule_name", operator: "eq", value: urlRuleName || undefined },
          { field: "path", operator: "contains", value: urlPath || undefined },
          { field: "action", operator: "eq", value: urlAction || undefined },
          { field: "country", operator: "eq", value: urlCountry || undefined },
        ],
        "replace",
      );
    }
  }, [searchParams]);

  const applyFilters = () => {
    setFilters(
      [
        { field: "host_code", operator: "eq", value: hostCode || undefined },
        { field: "client_ip", operator: "eq", value: clientIp || undefined },
        { field: "rule_id", operator: "eq", value: ruleId || undefined },
        { field: "rule_name", operator: "eq", value: ruleName || undefined },
        { field: "path", operator: "contains", value: path || undefined },
        { field: "action", operator: "eq", value: action || undefined },
        { field: "country", operator: "eq", value: countryFilter || undefined },
      ],
      "replace",
    );
    setCurrentPage(1);
    const params: Record<string, string> = {};
    if (hostCode) params.host_code = hostCode;
    if (clientIp) params.client_ip = clientIp;
    if (ruleId) params.rule_id = ruleId;
    if (ruleName) params.rule_name = ruleName;
    if (path) params.path = path;
    if (action) params.action = action;
    if (countryFilter) params.country = countryFilter;
    setSearchParams(params, { replace: true });
  };

  const onQuickTab = (tabKey: string) => {
    setActiveTab(tabKey);
    let tabAction: string | undefined;
    let tabRuleId = "";
    switch (tabKey) {
      case "blocked": tabAction = "block"; break;
      case "allowed": tabAction = "allow"; break;
      case "challenged": tabAction = "challenge"; break;
      case "honeypot": tabRuleId = "HONEY"; break;
      default: break;
    }
    setAction(tabAction);
    setRuleId(tabRuleId);
    setFilters(
      [
        { field: "host_code", operator: "eq", value: hostCode || undefined },
        { field: "client_ip", operator: "eq", value: clientIp || undefined },
        { field: "rule_id", operator: "eq", value: tabRuleId || undefined },
        { field: "rule_name", operator: "eq", value: ruleName || undefined },
        { field: "path", operator: "contains", value: path || undefined },
        { field: "action", operator: "eq", value: tabAction || undefined },
        { field: "country", operator: "eq", value: countryFilter || undefined },
      ],
      "replace",
    );
    setCurrentPage(1);
  };

  const data = Array.isArray(result?.data) ? result.data : [];
  const total = result?.total ?? 0;

  const uniqueCountries = useMemo(() => {
    const countries = new Set<string>();
    data.forEach((e) => {
      const c = e.geo_info?.country ?? e.country;
      if (c) countries.add(c);
    });
    return Array.from(countries).sort();
  }, [data]);

  const columns: ColumnsType<SecurityEvent> = [
    {
      title: t("security.time"),
      dataIndex: "created_at",
      width: 170,
      render: (v: string) => (
        <span style={{ color: "#8c8c8c", fontSize: 12 }}>{fmtDateTime(v)}</span>
      ),
    },
    {
      title: t("security.clientIP"),
      dataIndex: "client_ip",
      width: 140,
      render: (v) => (
        <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>{v}</span>
      ),
    },
    {
      title: t("security.method"),
      dataIndex: "method",
      width: 80,
      render: (v) => <Tag color={methodColor(v)}>{v}</Tag>,
    },
    {
      title: t("security.path"),
      dataIndex: "path",
      ellipsis: true,
      render: (v) => (
        <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }} title={v}>
          {v}
        </span>
      ),
    },
    {
      title: t("security.ruleName"),
      dataIndex: "rule_name",
      width: 180,
      ellipsis: true,
    },
    {
      title: t("security.ruleId"),
      dataIndex: "rule_id",
      width: 130,
      ellipsis: true,
      render: (v: string | undefined) =>
        v ? (
          <Typography.Text code copyable style={{ fontSize: 11 }}>
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
      render: (v: string) => <Tag color={actionColor(v)}>{v}</Tag>,
    },
    {
      title: "",
      key: "detail",
      width: 40,
      render: (_: unknown, record: SecurityEvent) => (
        <Button
          type="text"
          size="small"
          icon={<InfoCircleOutlined />}
          onClick={(e) => {
            e.stopPropagation();
            setSelectedEventId(record.id);
          }}
        />
      ),
    },
  ];

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <Typography.Title level={4} style={{ margin: 0 }}>
          {t("security.title")}
        </Typography.Title>
        <Space>
          <Switch
            checkedChildren="Auto"
            unCheckedChildren="Manual"
            checked={autoRefresh}
            onChange={setAutoRefresh}
          />
          <Button icon={<ReloadOutlined spin={tableQuery.isFetching} />} onClick={() => tableQuery.refetch()}>
            {t("common.refresh")}
          </Button>
        </Space>
      </Space>

      <Tabs
        activeKey={activeTab}
        onChange={onQuickTab}
        size="small"
        style={{ marginBottom: 4 }}
        items={[
          { key: "all", label: t("security.allActions") },
          { key: "blocked", label: t("security.block") },
          { key: "allowed", label: t("security.allow") },
          { key: "challenged", label: t("securityEvents.challengedEvents") },
          { key: "honeypot", label: t("securityEvents.honeypot") },
        ]}
      />

      <Card size="small">
        <Space wrap style={{ marginBottom: 12 }}>
          <Input
            placeholder={t("security.hostCode")}
            value={hostCode}
            onChange={(e) => setHostCode(e.target.value)}
            style={{ width: 180 }}
            onPressEnter={applyFilters}
          />
          <Input
            placeholder={t("security.clientIP")}
            value={clientIp}
            onChange={(e) => setClientIp(e.target.value)}
            style={{ width: 160 }}
            onPressEnter={applyFilters}
          />
          <Input
            placeholder={t("security.ruleId")}
            value={ruleId}
            onChange={(e) => setRuleId(e.target.value)}
            style={{ width: 130 }}
            onPressEnter={applyFilters}
          />
          <Input
            placeholder={t("security.ruleName")}
            value={ruleName}
            onChange={(e) => setRuleName(e.target.value)}
            style={{ width: 160 }}
            onPressEnter={applyFilters}
          />
          <Input
            placeholder={t("security.path")}
            value={path}
            onChange={(e) => setPath(e.target.value)}
            style={{ width: 200 }}
            onPressEnter={applyFilters}
          />
          <Select
            placeholder={t("security.allActions")}
            value={action}
            onChange={setAction}
            allowClear
            style={{ width: 140 }}
            options={[
              { value: "block", label: t("security.block") },
              { value: "allow", label: t("security.allow") },
              { value: "challenge", label: t("securityEvents.challengedEvents") },
            ]}
          />
          <Select
            placeholder={t("securityEvents.filterCountry")}
            value={countryFilter}
            onChange={(v) => setCountryFilter(v)}
            onClear={() => setCountryFilter(undefined)}
            allowClear
            showSearch
            style={{ width: 160 }}
            options={uniqueCountries.map((c) => ({ value: c, label: c }))}
          />
          <Button type="primary" onClick={applyFilters}>
            {t("security.filter")}
          </Button>
        </Space>

        <Table
          rowKey="id"
          size="small"
          dataSource={data}
          columns={columns}
          loading={tableQuery.isLoading}
          pagination={{
            current: currentPage,
            pageSize,
            total,
            onChange: (p, ps) => {
              setCurrentPage(p);
              setPageSize(ps);
            },
            showSizeChanger: true,
            pageSizeOptions: [20, 50, 100, 200],
            showTotal: (n) => `${t("common.total")}: ${n}`,
          }}
          locale={{ emptyText: t("security.noEvents") }}
          scroll={{ x: 800 }}
          onRow={(record) => ({
            style: { cursor: "pointer" },
            onClick: () => setSelectedEventId(record.id),
          })}
        />
      </Card>

      <EventDetailDrawer
        eventId={selectedEventId}
        onClose={() => setSelectedEventId(null)}
        onCreateRule={(ev) => setCreateRuleEvent(ev)}
      />

      <CreateRuleFromEventModal
        open={!!createRuleEvent}
        event={createRuleEvent}
        onClose={() => setCreateRuleEvent(null)}
        onCreated={(_id) => {
          setCreateRuleEvent(null);
          message.success(t("security.createRuleCreated"));
        }}
      />
    </Space>
  );
};
