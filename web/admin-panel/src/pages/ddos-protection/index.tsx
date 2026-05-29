import {
  Alert,
  Button,
  Card,
  Col,
  Form,
  Input,
  InputNumber,
  Popconfirm,
  Row,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Typography,
  App,
} from "antd";
import {
  ReloadOutlined,
  SaveOutlined,
  StopOutlined,
  ThunderboltOutlined,
  WarningOutlined,
  FireOutlined,
  DatabaseOutlined,
} from "@ant-design/icons";
import { useCustom, useCustomMutation } from "@refinedev/core";
import type { ColumnsType } from "antd/es/table";
import { useTranslation } from "react-i18next";
import { useEffect, useState } from "react";
import { KpiCard } from "../../components/kpi-card";

// ── Types ──────────────────────────────────────────────────────────────────────

interface DdosConfig {
  enabled: boolean;
  per_ip: { threshold_rps: number; window_secs: number };
  per_fingerprint: { threshold_rps: number; window_secs: number };
  ban_durations_secs: number[];
  store: { backend: "memory" | "redis"; redis_url?: string };
}

interface BanEntry {
  ip: string;
  banned_until_ms: number;
  ban_level: number;
  last_rps: number;
  reason: string;
}

interface DdosMetrics {
  active_bans: number;
  bursts_1h: number;
  bans_issued_1h: number;
  store_errors: number;
}

// ── Constants ──────────────────────────────────────────────────────────────────

const DEFAULT_CONFIG: DdosConfig = {
  enabled: true,
  per_ip: { threshold_rps: 100, window_secs: 10 },
  per_fingerprint: { threshold_rps: 200, window_secs: 10 },
  ban_durations_secs: [60, 300, 3600],
  store: { backend: "memory" },
};

// ── Countdown cell ─────────────────────────────────────────────────────────────

const BannedUntilCell: React.FC<{ bannedUntilMs: number }> = ({ bannedUntilMs }) => {
  const remaining = Math.max(0, Math.floor((bannedUntilMs - Date.now()) / 1000));
  if (remaining === 0) return <Tag color="default">expired</Tag>;
  if (remaining < 60)
    return (
      <Tag color="orange">
        {remaining}s
      </Tag>
    );
  const minutes = Math.floor(remaining / 60);
  if (minutes < 60)
    return (
      <Tag color="red">
        {minutes}m {remaining % 60}s
      </Tag>
    );
  const hours = Math.floor(minutes / 60);
  return (
    <Tag color="red">
      {hours}h {minutes % 60}m
    </Tag>
  );
};

// ── SectionCard helper ─────────────────────────────────────────────────────────

interface SectionCardProps {
  icon: React.ReactNode;
  title: string;
  extra?: React.ReactNode;
  children: React.ReactNode;
  loading?: boolean;
}

const SectionCard: React.FC<SectionCardProps> = ({ icon, title, extra, children, loading }) => (
  <Card
    size="small"
    loading={loading}
    title={
      <Space size={6}>
        {icon}
        <span>{title}</span>
      </Space>
    }
    extra={extra}
  >
    {children}
  </Card>
);

// ── Page ───────────────────────────────────────────────────────────────────────

export const DdosProtectionPage: React.FC = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();

  const [config, setConfig] = useState<DdosConfig>(DEFAULT_CONFIG);
  const [endpointMissing, setEndpointMissing] = useState(false);
  const [ipFilter, setIpFilter] = useState("");
  const [banLevelFilter, setBanLevelFilter] = useState<number | null>(null);
  const [form] = Form.useForm<DdosConfig>();

  const REFRESH_INTERVAL = 5_000;

  // ── Metrics ──────────────────────────────────────────────────────────────────

  const { result: metricsResult, query: metricsQuery } = useCustom<DdosMetrics>({
    url: "/api/ddos/metrics",
    method: "get",
    queryOptions: { refetchInterval: REFRESH_INTERVAL, staleTime: 0, retry: false },
    errorNotification: false,
  });

  useEffect(() => {
    if (metricsQuery.isError) setEndpointMissing(true);
  }, [metricsQuery.isError]);

  const metrics = metricsResult?.data;

  // ── Config load ──────────────────────────────────────────────────────────────

  const { result: configResult, query: configQuery } = useCustom<DdosConfig>({
    url: "/api/ddos/config",
    method: "get",
    queryOptions: { retry: false },
    errorNotification: false,
  });

  useEffect(() => {
    if (configResult?.data) {
      const raw = configResult.data;
      const loaded = (raw as { data?: DdosConfig }).data ?? raw as DdosConfig;
      if (loaded?.enabled !== undefined) {
        setConfig(loaded);
        form.setFieldsValue({ ...loaded, ban_durations_secs: loaded.ban_durations_secs ?? [60, 300, 3600] });
        setEndpointMissing(false);
      }
    }
  }, [configResult]);

  useEffect(() => {
    if (configQuery.isError) setEndpointMissing(true);
  }, [configQuery.isError]);

  useEffect(() => {
    if (configQuery.error) setEndpointMissing(true);
  }, [configQuery.error]);

  // ── Ban table ────────────────────────────────────────────────────────────────

  const { result: banResult, query: banQuery } = useCustom<{ data: BanEntry[] }>({
    url: "/api/ddos/ban-table",
    method: "get",
    queryOptions: {
      refetchInterval: REFRESH_INTERVAL,
      staleTime: 0,
      retry: false,
    },
  });

  const rawBans: BanEntry[] = Array.isArray(banResult?.data?.data)
    ? banResult.data.data
    : Array.isArray(banResult?.data)
    ? (banResult.data as unknown as BanEntry[])
    : [];

  const filteredBans = rawBans.filter((b) => {
    const matchIp = ipFilter ? b.ip.includes(ipFilter) : true;
    const matchLevel = banLevelFilter !== null ? b.ban_level === banLevelFilter : true;
    return matchIp && matchLevel;
  });

  // ── Unban ────────────────────────────────────────────────────────────────────

  const { mutate: unbanIp } = useCustomMutation();

  const onUnban = (ip: string) => {
    unbanIp(
      { url: `/api/ddos/ban-table/${encodeURIComponent(ip)}`, method: "delete", values: {} },
      {
        onSuccess: () => {
          message.success(t("ddos.unbanned", { ip }));
          banQuery.refetch();
        },
        onError: (err) => message.error(err.message),
      },
    );
  };

  // ── Save config ──────────────────────────────────────────────────────────────

  const { mutate: saveConfig, mutation: saveMutation } = useCustomMutation();
  const saving = saveMutation.isPending;

  const onSave = async () => {
    const values = await form.validateFields();
    saveConfig(
      { url: "/api/ddos/config", method: "put", values },
      {
        onSuccess: () => message.success(t("ddos.saved")),
        onError: (err) => message.error(err.message),
      },
    );
  };

  const storeBackend = Form.useWatch("store", form);
  const currentBackend = storeBackend?.backend ?? config.store.backend;

  // ── Ban table columns ────────────────────────────────────────────────────────

  const banColumns: ColumnsType<BanEntry> = [
    {
      title: t("ddos.ip"),
      dataIndex: "ip",
      width: 150,
      render: (v: string) => (
        <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>{v}</span>
      ),
    },
    {
      title: t("ddos.banLevel"),
      dataIndex: "ban_level",
      width: 90,
      render: (v: number) => (
        <Tag color={v >= 3 ? "red" : v === 2 ? "orange" : "gold"}>L{v}</Tag>
      ),
    },
    {
      title: t("ddos.bannedUntil"),
      dataIndex: "banned_until_ms",
      width: 130,
      render: (v: number) => <BannedUntilCell bannedUntilMs={v} />,
    },
    {
      title: t("ddos.lastRps"),
      dataIndex: "last_rps",
      width: 100,
      render: (v: number) => (
        <span style={{ fontFamily: "ui-monospace, monospace" }}>{v} rps</span>
      ),
    },
    {
      title: t("ddos.reason"),
      dataIndex: "reason",
      ellipsis: true,
      render: (v: string) => (
        <span style={{ fontSize: 12, color: "#595959" }}>{v}</span>
      ),
    },
    {
      title: "",
      key: "actions",
      width: 90,
      render: (_: unknown, r: BanEntry) => (
        <Popconfirm
          title={t("ddos.unbanConfirm", { ip: r.ip })}
          onConfirm={() => onUnban(r.ip)}
        >
          <Button size="small" danger icon={<StopOutlined />}>
            {t("ddos.unban")}
          </Button>
        </Popconfirm>
      ),
    },
  ];

  const banLevelOptions = [1, 2, 3].map((l) => ({ value: l, label: `Level ${l}` }));

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      {/* Header */}
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <div>
          <Typography.Title level={4} style={{ margin: 0 }}>
            {t("ddos.title")}
          </Typography.Title>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {t("ddos.subtitle")}
          </Typography.Text>
        </div>
        <Space>
          <Button
            icon={<ReloadOutlined spin={configQuery.isLoading || metricsQuery.isLoading} />}
            onClick={() => {
              configQuery.refetch();
              metricsQuery.refetch();
              banQuery.refetch();
            }}
          >
            {t("common.reload")}
          </Button>
          <Button
            type="primary"
            icon={<SaveOutlined />}
            loading={saving}
            onClick={onSave}
            disabled={endpointMissing}
          >
            {t("common.save")}
          </Button>
        </Space>
      </Space>

      {/* Endpoint unavailable alert */}
      {endpointMissing && (
        <Alert
          type="warning"
          showIcon
          message={t("ddos.endpointMissing")}
          description={t("ddos.endpointMissingDesc")}
        />
      )}

      {/* KPI cards — auto-refresh every 5s */}
      <Row gutter={[12, 12]}>
        <Col xs={12} sm={6}>
          <KpiCard
            label={t("ddos.activeBans")}
            value={metrics?.active_bans ?? "—"}
            icon={StopOutlined}
            color="red"
            loading={metricsQuery.isLoading}
          />
        </Col>
        <Col xs={12} sm={6}>
          <KpiCard
            label={t("ddos.bursts1h")}
            value={metrics?.bursts_1h ?? "—"}
            icon={FireOutlined}
            color="orange"
            loading={metricsQuery.isLoading}
          />
        </Col>
        <Col xs={12} sm={6}>
          <KpiCard
            label={t("ddos.bansIssued1h")}
            value={metrics?.bans_issued_1h ?? "—"}
            icon={WarningOutlined}
            color="purple"
            loading={metricsQuery.isLoading}
          />
        </Col>
        <Col xs={12} sm={6}>
          <KpiCard
            label={t("ddos.storeErrors")}
            value={metrics?.store_errors ?? "—"}
            icon={DatabaseOutlined}
            color={metrics?.store_errors ? "red" : "green"}
            loading={metricsQuery.isLoading}
          />
        </Col>
      </Row>

      {/* Config form */}
      <SectionCard
        icon={<ThunderboltOutlined style={{ color: "#1677ff" }} />}
        title={t("ddos.configuration")}
      >
        <Form
          form={form}
          layout="vertical"
          initialValues={DEFAULT_CONFIG}
          size="small"
        >
          <Form.Item name="enabled" valuePropName="checked" label={t("ddos.enabled")}>
            <Switch />
          </Form.Item>

          <Row gutter={24}>
            <Col xs={24} md={12}>
              <Card size="small" title={t("ddos.perIp")} style={{ marginBottom: 12 }}>
                <Row gutter={12}>
                  <Col span={12}>
                    <Form.Item
                      name={["per_ip", "threshold_rps"]}
                      label={t("ddos.thresholdRps")}
                      rules={[{ required: true }]}
                    >
                      <InputNumber min={1} addonAfter="rps" style={{ width: "100%" }} />
                    </Form.Item>
                  </Col>
                  <Col span={12}>
                    <Form.Item
                      name={["per_ip", "window_secs"]}
                      label={t("ddos.windowSecs")}
                      rules={[{ required: true }]}
                    >
                      <InputNumber min={1} addonAfter="s" style={{ width: "100%" }} />
                    </Form.Item>
                  </Col>
                </Row>
              </Card>
            </Col>

            <Col xs={24} md={12}>
              <Card size="small" title={t("ddos.perFingerprint")} style={{ marginBottom: 12 }}>
                <Row gutter={12}>
                  <Col span={12}>
                    <Form.Item
                      name={["per_fingerprint", "threshold_rps"]}
                      label={t("ddos.thresholdRps")}
                      rules={[{ required: true }]}
                    >
                      <InputNumber min={1} addonAfter="rps" style={{ width: "100%" }} />
                    </Form.Item>
                  </Col>
                  <Col span={12}>
                    <Form.Item
                      name={["per_fingerprint", "window_secs"]}
                      label={t("ddos.windowSecs")}
                      rules={[{ required: true }]}
                    >
                      <InputNumber min={1} addonAfter="s" style={{ width: "100%" }} />
                    </Form.Item>
                  </Col>
                </Row>
              </Card>
            </Col>
          </Row>

          {/* Ban escalation ladder */}
          <Card size="small" title={t("ddos.banEscalation")} style={{ marginBottom: 12 }}>
            <Space wrap>
              <Form.Item
                name={["ban_durations_secs", 0]}
                label={t("ddos.banLevel1")}
                rules={[{ required: true }]}
                style={{ marginBottom: 0 }}
              >
                <InputNumber min={1} addonAfter="s" style={{ width: 130 }} />
              </Form.Item>
              <Form.Item
                name={["ban_durations_secs", 1]}
                label={t("ddos.banLevel2")}
                rules={[{ required: true }]}
                style={{ marginBottom: 0 }}
              >
                <InputNumber min={1} addonAfter="s" style={{ width: 130 }} />
              </Form.Item>
              <Form.Item
                name={["ban_durations_secs", 2]}
                label={t("ddos.banLevel3")}
                rules={[{ required: true }]}
                style={{ marginBottom: 0 }}
              >
                <InputNumber min={1} addonAfter="s" style={{ width: 130 }} />
              </Form.Item>
            </Space>
          </Card>

          {/* Store backend */}
          <Card size="small" title={t("ddos.storeBackend")} style={{ marginBottom: 0 }}>
            <Row gutter={12}>
              <Col xs={24} sm={8}>
                <Form.Item
                  name={["store", "backend"]}
                  label={t("ddos.backend")}
                  rules={[{ required: true }]}
                >
                  <Select
                    options={[
                      { value: "memory", label: t("ddos.backendMemory") },
                      { value: "redis", label: t("ddos.backendRedis") },
                    ]}
                  />
                </Form.Item>
              </Col>
              {currentBackend === "redis" && (
                <Col xs={24} sm={16}>
                  <Form.Item
                    name={["store", "redis_url"]}
                    label={t("ddos.redisUrl")}
                    rules={[{ required: true, message: t("ddos.redisUrlRequired") }]}
                  >
                    <Input
                      placeholder="redis://127.0.0.1:6379"
                      style={{ fontFamily: "ui-monospace, monospace" }}
                    />
                  </Form.Item>
                </Col>
              )}
            </Row>
          </Card>
        </Form>
      </SectionCard>

      {/* Ban table */}
      <SectionCard
        icon={<StopOutlined style={{ color: "#f5222d" }} />}
        title={t("ddos.banTable")}
        extra={
          <Space size={8}>
            <Input
              size="small"
              placeholder={t("ddos.filterIp")}
              value={ipFilter}
              onChange={(e) => setIpFilter(e.target.value)}
              allowClear
              style={{ width: 160 }}
            />
            <Select
              size="small"
              placeholder={t("ddos.filterBanLevel")}
              value={banLevelFilter}
              onChange={setBanLevelFilter}
              allowClear
              style={{ width: 110 }}
              options={banLevelOptions}
            />
            <Button
              size="small"
              icon={<ReloadOutlined spin={banQuery.isFetching} />}
              onClick={() => banQuery.refetch()}
            />
          </Space>
        }
      >
        <Table<BanEntry>
          rowKey="ip"
          size="small"
          dataSource={filteredBans}
          columns={banColumns}
          loading={banQuery.isLoading}
          pagination={{ pageSize: 20, showSizeChanger: false }}
          locale={{ emptyText: t("ddos.noBans") }}
          scroll={{ x: 700 }}
        />
      </SectionCard>
    </Space>
  );
};
