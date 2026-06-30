import {
  Card,
  Row,
  Col,
  Typography,
  Space,
  Button,
  Table,
  Tag,
  Switch,
  Statistic,
  Form,
  Input,
  InputNumber,
  App,
} from "antd";
import { ReloadOutlined, SaveOutlined } from "@ant-design/icons";
import { useTable, useList, useCustom, useCustomMutation } from "@refinedev/core";
import { Column } from "@ant-design/plots";
import type { ColumnsType } from "antd/es/table";
import { useTranslation } from "react-i18next";
import { useEffect, useMemo, useState } from "react";
import type { SecurityEvent } from "../../types/api";
import { fmtDateTime } from "../../utils/format";

// ── Helpers ────────────────────────────────────────────────────────────────────

function actionColor(action: string): string {
  if (action === "block") return "red";
  if (action === "challenge") return "orange";
  return "default";
}

function rulePrefix(ruleId?: string): "TX-SEQ" | "TX-WITHDRAW" | "TX-LIMIT" | "TX-OTHER" {
  if (!ruleId) return "TX-OTHER";
  if (ruleId.startsWith("TX-SEQ")) return "TX-SEQ";
  if (ruleId.startsWith("TX-WITHDRAW")) return "TX-WITHDRAW";
  if (ruleId.startsWith("TX-LIMIT")) return "TX-LIMIT";
  return "TX-OTHER";
}

const PREFIX_COLOR: Record<string, string> = {
  "TX-SEQ": "blue",
  "TX-WITHDRAW": "orange",
  "TX-LIMIT": "purple",
  "TX-OTHER": "default",
};

// ── TX-velocity config (editable, C2 / FR-012) ──────────────────────────────────

interface TxVelocityConfig {
  schema_version?: number;
  enabled: boolean;
  session_cookie: string;
  signal_cooldown_ms: number;
  session_ttl_secs: number;
  janitor_period_secs: number;
  dedupe_window_ms: number;
  endpoint_roles?: Array<{ role: string; path: string }>;
  classifiers?: {
    sequence?: { min_human_ms: number } | null;
    withdrawal_velocity?: { max_count: number; window_ms: number } | null;
    limit_change_velocity?: { max_count: number; window_ms: number } | null;
  };
}

const TxVelocityConfigCard: React.FC = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [form] = Form.useForm();
  const [loaded, setLoaded] = useState<TxVelocityConfig | null>(null);

  const cfgQuery = useCustom<TxVelocityConfig>({
    url: "/api/tx-velocity/config",
    method: "get",
    queryOptions: { staleTime: 10_000, retry: false },
    errorNotification: false,
  });

  useEffect(() => {
    const raw = cfgQuery.result?.data as TxVelocityConfig | undefined;
    if (!raw) return;
    setLoaded(raw);
    form.setFieldsValue({
      enabled: raw.enabled,
      session_cookie: raw.session_cookie,
      signal_cooldown_ms: raw.signal_cooldown_ms,
      session_ttl_secs: raw.session_ttl_secs,
      janitor_period_secs: raw.janitor_period_secs,
      dedupe_window_ms: raw.dedupe_window_ms,
      seq_min_human_ms: raw.classifiers?.sequence?.min_human_ms,
      withdraw_max_count: raw.classifiers?.withdrawal_velocity?.max_count,
      withdraw_window_ms: raw.classifiers?.withdrawal_velocity?.window_ms,
      limit_max_count: raw.classifiers?.limit_change_velocity?.max_count,
      limit_window_ms: raw.classifiers?.limit_change_velocity?.window_ms,
    });
  }, [cfgQuery.result]);

  const { mutate: save, mutation } = useCustomMutation();

  const onSave = async () => {
    const v = await form.validateFields();
    const classifiers: NonNullable<TxVelocityConfig["classifiers"]> = {};
    if (v.seq_min_human_ms != null) classifiers.sequence = { min_human_ms: v.seq_min_human_ms };
    if (v.withdraw_max_count != null && v.withdraw_window_ms != null)
      classifiers.withdrawal_velocity = { max_count: v.withdraw_max_count, window_ms: v.withdraw_window_ms };
    if (v.limit_max_count != null && v.limit_window_ms != null)
      classifiers.limit_change_velocity = { max_count: v.limit_max_count, window_ms: v.limit_window_ms };

    const payload: TxVelocityConfig = {
      ...(loaded?.schema_version ? { schema_version: loaded.schema_version } : {}),
      enabled: v.enabled ?? false,
      session_cookie: v.session_cookie,
      signal_cooldown_ms: v.signal_cooldown_ms,
      session_ttl_secs: v.session_ttl_secs,
      janitor_period_secs: v.janitor_period_secs,
      dedupe_window_ms: v.dedupe_window_ms,
      endpoint_roles: loaded?.endpoint_roles ?? [],
      classifiers,
    };

    save(
      { url: "/api/tx-velocity/config", method: "put", values: payload },
      {
        onSuccess: () => {
          message.success(t("txVelocity.configSaved", { defaultValue: "Configuration saved" }));
          cfgQuery.query.refetch();
        },
        onError: (e) => message.error(e.message),
      },
    );
  };

  return (
    <Card
      title={t("txVelocity.configInfo")}
      extra={<Tag color="cyan">configs/tx-velocity.yaml</Tag>}
      loading={cfgQuery.query.isLoading}
    >
      {cfgQuery.query.isError ? (
        <Typography.Text type="danger">
          {t("txVelocity.configLoadError", { defaultValue: "Failed to load configuration" })}
        </Typography.Text>
      ) : (
        <Form form={form} layout="vertical" size="small">
          <Form.Item
            name="enabled"
            label={t("txVelocity.cfgEnabled", { defaultValue: "Detection enabled" })}
            valuePropName="checked"
          >
            <Switch />
          </Form.Item>
          <Row gutter={12}>
            <Col span={12}>
              <Form.Item
                name="seq_min_human_ms"
                label={t("txVelocity.cfgSeqMinHumanMs", { defaultValue: "Sequence min human (ms)" })}
              >
                <InputNumber min={0} style={{ width: "100%" }} addonAfter="ms" />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item
                name="session_cookie"
                label={t("txVelocity.cfgSessionCookie", { defaultValue: "Session cookie" })}
              >
                <Input />
              </Form.Item>
            </Col>
          </Row>
          <Row gutter={12}>
            <Col span={12}>
              <Form.Item
                name="withdraw_max_count"
                label={t("txVelocity.cfgWithdrawMax", { defaultValue: "Withdrawal max count" })}
              >
                <InputNumber min={0} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item
                name="withdraw_window_ms"
                label={t("txVelocity.cfgWithdrawWindowMs", { defaultValue: "Withdrawal window (ms)" })}
              >
                <InputNumber min={0} style={{ width: "100%" }} addonAfter="ms" />
              </Form.Item>
            </Col>
          </Row>
          <Row gutter={12}>
            <Col span={12}>
              <Form.Item
                name="limit_max_count"
                label={t("txVelocity.cfgLimitMax", { defaultValue: "Limit-change max count" })}
              >
                <InputNumber min={0} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item
                name="limit_window_ms"
                label={t("txVelocity.cfgLimitWindowMs", { defaultValue: "Limit-change window (ms)" })}
              >
                <InputNumber min={0} style={{ width: "100%" }} addonAfter="ms" />
              </Form.Item>
            </Col>
          </Row>
          <Row gutter={12}>
            <Col span={8}>
              <Form.Item
                name="signal_cooldown_ms"
                label={t("txVelocity.cfgCooldownMs", { defaultValue: "Signal cooldown (ms)" })}
              >
                <InputNumber min={0} style={{ width: "100%" }} addonAfter="ms" />
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item
                name="session_ttl_secs"
                label={t("txVelocity.cfgSessionTtl", { defaultValue: "Session TTL (s)" })}
              >
                <InputNumber min={1} style={{ width: "100%" }} addonAfter="s" />
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item
                name="janitor_period_secs"
                label={t("txVelocity.cfgJanitor", { defaultValue: "Janitor period (s)" })}
              >
                <InputNumber min={1} style={{ width: "100%" }} addonAfter="s" />
              </Form.Item>
            </Col>
          </Row>
          <Button type="primary" icon={<SaveOutlined />} loading={mutation.isPending} onClick={onSave}>
            {t("common.save")}
          </Button>
        </Form>
      )}
    </Card>
  );
};

// ── Page ───────────────────────────────────────────────────────────────────────

export const TxVelocityPage: React.FC = () => {
  const { t } = useTranslation();
  const [autoRefresh, setAutoRefresh] = useState(true);
  const interval = autoRefresh ? 30_000 : (false as const);

  // ── KPI counts (one useList per signal family, page_size=1 for bandwidth) ──

  const seqList = useList<SecurityEvent>({
    resource: "security-events",
    pagination: { mode: "server", currentPage: 1, pageSize: 1 },
    filters: [{ field: "rule_id_prefix", operator: "eq", value: "TX-SEQ-" }],
    queryOptions: { staleTime: 0, refetchInterval: interval },
  });

  const withdrawList = useList<SecurityEvent>({
    resource: "security-events",
    pagination: { mode: "server", currentPage: 1, pageSize: 1 },
    filters: [{ field: "rule_id_prefix", operator: "eq", value: "TX-WITHDRAW-" }],
    queryOptions: { staleTime: 0, refetchInterval: interval },
  });

  const limitList = useList<SecurityEvent>({
    resource: "security-events",
    pagination: { mode: "server", currentPage: 1, pageSize: 1 },
    filters: [{ field: "rule_id_prefix", operator: "eq", value: "TX-LIMIT-" }],
    queryOptions: { staleTime: 0, refetchInterval: interval },
  });

  const seqTotal = seqList.result?.total ?? 0;
  const withdrawTotal = withdrawList.result?.total ?? 0;
  const limitTotal = limitList.result?.total ?? 0;
  const grandTotal = seqTotal + withdrawTotal + limitTotal;

  // ── Events table (all TX- events via permanent filter) ─────────────────────

  const { tableQuery, result, currentPage, setCurrentPage, pageSize, setPageSize } =
    useTable<SecurityEvent>({
      resource: "security-events",
      pagination: { currentPage: 1, pageSize: 20, mode: "server" },
      filters: {
        permanent: [{ field: "rule_id_prefix", operator: "eq", value: "TX-" }],
      },
      queryOptions: { staleTime: 0, refetchInterval: interval },
    });

  const tableData = Array.isArray(result?.data) ? result.data : [];
  const tableTotal = result?.total ?? 0;

  // ── Chart data built from KPI totals ────────────────────────────────────────

  const chartData = useMemo(
    () => [
      { type: "TX-SEQ", count: seqTotal },
      { type: "TX-WITHDRAW", count: withdrawTotal },
      { type: "TX-LIMIT", count: limitTotal },
    ],
    [seqTotal, withdrawTotal, limitTotal],
  );

  function refetchAll() {
    seqList.query.refetch();
    withdrawList.query.refetch();
    limitList.query.refetch();
    tableQuery.refetch();
  }

  // ── Table columns ──────────────────────────────────────────────────────────

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
      title: t("txVelocity.signalType"),
      dataIndex: "rule_id",
      width: 140,
      render: (v: string) => {
        const p = rulePrefix(v);
        return <Tag color={PREFIX_COLOR[p]}>{p}</Tag>;
      },
    },
    {
      title: t("security.ruleId"),
      dataIndex: "rule_id",
      width: 180,
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
      title: t("security.clientIP"),
      dataIndex: "client_ip",
      width: 140,
      render: (v) => (
        <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>{v}</span>
      ),
    },
    {
      title: t("security.action"),
      dataIndex: "action",
      width: 100,
      render: (v: string) => <Tag color={actionColor(v)}>{v}</Tag>,
    },
    {
      title: t("security.ruleName"),
      dataIndex: "rule_name",
      ellipsis: true,
    },
  ];

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      {/* Header */}
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <div>
          <Typography.Title level={4} style={{ margin: 0 }}>
            {t("txVelocity.title")}
          </Typography.Title>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {t("txVelocity.subtitle")}
          </Typography.Text>
        </div>
        <Space>
          <Switch
            checkedChildren="Auto"
            unCheckedChildren="Manual"
            checked={autoRefresh}
            onChange={setAutoRefresh}
          />
          <Button
            icon={<ReloadOutlined spin={tableQuery.isFetching} />}
            onClick={refetchAll}
          >
            {t("common.refresh")}
          </Button>
        </Space>
      </Space>

      {/* KPI row */}
      <Row gutter={[16, 16]}>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic
              title={t("txVelocity.seqCount")}
              value={seqTotal}
              valueStyle={{ color: "#1677ff" }}
              loading={seqList.query.isLoading}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic
              title={t("txVelocity.withdrawCount")}
              value={withdrawTotal}
              valueStyle={{ color: "#fa8c16" }}
              loading={withdrawList.query.isLoading}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic
              title={t("txVelocity.limitCount")}
              value={limitTotal}
              valueStyle={{ color: "#722ed1" }}
              loading={limitList.query.isLoading}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic
              title={t("txVelocity.totalCount")}
              value={grandTotal}
              valueStyle={{ color: "#cf1322" }}
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        {/* Signal distribution chart */}
        <Col xs={24} lg={12}>
          <Card title={t("txVelocity.distribution")}>
            {grandTotal > 0 ? (
              <Column
                data={chartData}
                xField="type"
                yField="count"
                height={220}
                animate={false}
              />
            ) : (
              <div
                style={{
                  height: 220,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                }}
              >
                <Typography.Text type="secondary">{t("txVelocity.noEvents")}</Typography.Text>
              </div>
            )}
          </Card>
        </Col>

        {/* Config thresholds — editable (C2 / FR-012 + FR-031 hot-reload) */}
        <Col xs={24} lg={12}>
          <TxVelocityConfigCard />
        </Col>
      </Row>

      {/* Recent TX events table */}
      <Card size="small" title={t("txVelocity.recentEvents")}>
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
            pageSizeOptions: [20, 50, 100],
            showTotal: (n) => `${t("common.total")}: ${n}`,
          }}
          locale={{ emptyText: t("txVelocity.noEvents") }}
          scroll={{ x: 800 }}
        />
      </Card>
    </Space>
  );
};
