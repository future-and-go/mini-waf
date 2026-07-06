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

// Mirrors backend `DdosFileConfig` (crates/waf-engine/src/checks/ddos/config.rs).
// The PUT endpoint deserializes with deny_unknown_fields, so this shape must
// match the backend schema exactly.

interface TierThresholds {
  per_fp_threshold: number;
  per_fp_window_s: number;
  per_tier_threshold: number;
  per_tier_window_s: number;
}

type TierKey = "critical" | "high" | "medium" | "catch_all";

interface RedisCfg {
  url: string;
  key_prefix: string;
  op_timeout_ms: number;
}

interface DdosConfig {
  schema_version: number;
  enabled: boolean;
  hot_reload: boolean;
  // Tiers set to null are not DDoS-protected (the check skips them).
  tiers: Partial<Record<TierKey, TierThresholds | null>>;
  gc_interval_s: number;
  max_keys: number;
  // null ⇒ memory-only standalone mode.
  redis: RedisCfg | null;
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

const TIER_KEYS: TierKey[] = ["critical", "high", "medium", "catch_all"];

const TIER_LABELS: Record<TierKey, string> = {
  critical: "ddos.tierCritical",
  high: "ddos.tierHigh",
  medium: "ddos.tierMedium",
  catch_all: "ddos.tierCatchAll",
};

// Mirrors backend serde defaults (empty ddos.yaml ⇒ inert subsystem).
const DEFAULT_CONFIG: DdosConfig = {
  schema_version: 1,
  enabled: false,
  hot_reload: true,
  tiers: {},
  gc_interval_s: 60,
  max_keys: 100_000,
  redis: null,
};

// Seed values shown when the operator first enables a tier / the redis block.
const DEFAULT_TIER: TierThresholds = {
  per_fp_threshold: 100,
  per_fp_window_s: 10,
  per_tier_threshold: 1000,
  per_tier_window_s: 10,
};

const DEFAULT_REDIS: RedisCfg = {
  url: "redis://127.0.0.1:6379",
  key_prefix: "wafddos:",
  op_timeout_ms: 50,
};

// Form store shape: null tiers/redis are replaced by seed values so the
// inputs always have content; toggles decide what actually gets sent.
const INITIAL_FORM: DdosConfig = {
  ...DEFAULT_CONFIG,
  tiers: {
    critical: DEFAULT_TIER,
    high: DEFAULT_TIER,
    medium: DEFAULT_TIER,
    catch_all: DEFAULT_TIER,
  },
  redis: DEFAULT_REDIS,
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
  const [tierEnabled, setTierEnabled] = useState<Record<TierKey, boolean>>({
    critical: false,
    high: false,
    medium: false,
    catch_all: false,
  });
  const [redisEnabled, setRedisEnabled] = useState(false);
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
        setTierEnabled({
          critical: !!loaded.tiers?.critical,
          high: !!loaded.tiers?.high,
          medium: !!loaded.tiers?.medium,
          catch_all: !!loaded.tiers?.catch_all,
        });
        setRedisEnabled(!!loaded.redis);
        form.setFieldsValue({
          ...loaded,
          tiers: Object.fromEntries(
            TIER_KEYS.map((k) => [k, loaded.tiers?.[k] ?? DEFAULT_TIER]),
          ),
          redis: loaded.redis ?? DEFAULT_REDIS,
        });
        setEndpointMissing(false);
      }
    }
    // Depend on the stable payload, not the useCustom() result wrapper — the
    // wrapper is rebuilt every render and would re-hydrate (and clobber) the
    // form and tier/redis toggles on every re-render.
  }, [configResult?.data]);

  useEffect(() => {
    if (configQuery.isError) setEndpointMissing(true);
  }, [configQuery.isError]);

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
    // Build the exact backend `DdosFileConfig` shape: disabled tiers and a
    // disabled redis block are sent as null, matching operator YAML semantics.
    const payload: DdosConfig = {
      schema_version: config.schema_version ?? 1,
      enabled: values.enabled,
      hot_reload: values.hot_reload,
      gc_interval_s: values.gc_interval_s,
      max_keys: values.max_keys,
      tiers: Object.fromEntries(
        TIER_KEYS.map((k) => [k, tierEnabled[k] ? values.tiers?.[k] ?? DEFAULT_TIER : null]),
      ),
      redis: redisEnabled ? values.redis ?? DEFAULT_REDIS : null,
    };
    saveConfig(
      { url: "/api/ddos/config", method: "put", values: payload },
      {
        onSuccess: () => {
          message.success(t("ddos.saved"));
          // Refresh the cached config so remounts within staleTime hydrate
          // from the saved values instead of the pre-save cache.
          configQuery.refetch();
        },
        onError: (err) => message.error(err.message),
      },
    );
  };

  const onToggleTier = (k: TierKey, on: boolean) => {
    setTierEnabled((prev) => ({ ...prev, [k]: on }));
    if (on && form.getFieldValue(["tiers", k, "per_fp_threshold"]) === undefined) {
      form.setFieldValue(["tiers", k], DEFAULT_TIER);
    }
  };

  const onToggleRedis = (on: boolean) => {
    setRedisEnabled(on);
    if (on && form.getFieldValue(["redis", "url"]) === undefined) {
      form.setFieldValue("redis", DEFAULT_REDIS);
    }
  };

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
          initialValues={INITIAL_FORM}
          size="small"
        >
          <Row gutter={24}>
            <Col>
              <Form.Item name="enabled" valuePropName="checked" label={t("ddos.enabled")}>
                <Switch />
              </Form.Item>
            </Col>
            <Col>
              <Form.Item name="hot_reload" valuePropName="checked" label={t("ddos.hotReload")}>
                <Switch />
              </Form.Item>
            </Col>
            <Col>
              <Form.Item
                name="gc_interval_s"
                label={t("ddos.gcInterval")}
                rules={[{ required: true }]}
              >
                <InputNumber min={1} addonAfter="s" style={{ width: 130 }} />
              </Form.Item>
            </Col>
            <Col>
              <Form.Item name="max_keys" label={t("ddos.maxKeys")} rules={[{ required: true }]}>
                <InputNumber min={1} style={{ width: 150 }} />
              </Form.Item>
            </Col>
          </Row>

          {/* Per-tier thresholds — tiers left off are not DDoS-protected */}
          <Row gutter={24}>
            {TIER_KEYS.map((k) => (
              <Col xs={24} md={12} key={k}>
                <Card
                  size="small"
                  title={t(TIER_LABELS[k])}
                  style={{ marginBottom: 12 }}
                  extra={
                    <Switch
                      size="small"
                      checked={tierEnabled[k]}
                      onChange={(on) => onToggleTier(k, on)}
                    />
                  }
                >
                  {tierEnabled[k] ? (
                    <Row gutter={12}>
                      <Col span={12}>
                        <Form.Item
                          name={["tiers", k, "per_fp_threshold"]}
                          label={t("ddos.perFpThreshold")}
                          rules={[{ required: true }]}
                        >
                          <InputNumber min={1} addonAfter="req" style={{ width: "100%" }} />
                        </Form.Item>
                      </Col>
                      <Col span={12}>
                        <Form.Item
                          name={["tiers", k, "per_fp_window_s"]}
                          label={t("ddos.perFpWindow")}
                          rules={[{ required: true }]}
                        >
                          <InputNumber min={1} addonAfter="s" style={{ width: "100%" }} />
                        </Form.Item>
                      </Col>
                      <Col span={12}>
                        <Form.Item
                          name={["tiers", k, "per_tier_threshold"]}
                          label={t("ddos.perTierThreshold")}
                          rules={[{ required: true }]}
                          style={{ marginBottom: 0 }}
                        >
                          <InputNumber min={1} addonAfter="req" style={{ width: "100%" }} />
                        </Form.Item>
                      </Col>
                      <Col span={12}>
                        <Form.Item
                          name={["tiers", k, "per_tier_window_s"]}
                          label={t("ddos.perTierWindow")}
                          rules={[{ required: true }]}
                          style={{ marginBottom: 0 }}
                        >
                          <InputNumber min={1} addonAfter="s" style={{ width: "100%" }} />
                        </Form.Item>
                      </Col>
                    </Row>
                  ) : (
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      {t("ddos.tierUnprotected")}
                    </Typography.Text>
                  )}
                </Card>
              </Col>
            ))}
          </Row>

          {/* Optional Redis backend — off ⇒ memory-only standalone mode */}
          <Card
            size="small"
            title={t("ddos.redisBackend")}
            style={{ marginBottom: 0 }}
            extra={<Switch size="small" checked={redisEnabled} onChange={onToggleRedis} />}
          >
            {redisEnabled ? (
              <Row gutter={12}>
                <Col xs={24} sm={12}>
                  <Form.Item
                    name={["redis", "url"]}
                    label={t("ddos.redisUrl")}
                    rules={[{ required: true, message: t("ddos.redisUrlRequired") }]}
                  >
                    <Input
                      placeholder="redis://127.0.0.1:6379"
                      style={{ fontFamily: "ui-monospace, monospace" }}
                    />
                  </Form.Item>
                </Col>
                <Col xs={12} sm={6}>
                  <Form.Item
                    name={["redis", "key_prefix"]}
                    label={t("ddos.redisKeyPrefix")}
                    rules={[{ required: true }]}
                  >
                    <Input style={{ fontFamily: "ui-monospace, monospace" }} />
                  </Form.Item>
                </Col>
                <Col xs={12} sm={6}>
                  <Form.Item
                    name={["redis", "op_timeout_ms"]}
                    label={t("ddos.redisOpTimeout")}
                    rules={[{ required: true }]}
                  >
                    <InputNumber min={1} addonAfter="ms" style={{ width: "100%" }} />
                  </Form.Item>
                </Col>
              </Row>
            ) : (
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                {t("ddos.redisDisabled")}
              </Typography.Text>
            )}
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
