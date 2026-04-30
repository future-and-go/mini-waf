import {
  Alert,
  Badge,
  Button,
  Card,
  Col,
  Descriptions,
  Form,
  InputNumber,
  Row,
  Select,
  Slider,
  Space,
  Switch,
  Tag,
  Tooltip,
  Typography,
  App,
} from "antd";
import {
  BugOutlined,
  CheckCircleOutlined,
  ExperimentOutlined,
  GlobalOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  SaveOutlined,
  SecurityScanOutlined,
  ThunderboltOutlined,
} from "@ant-design/icons";
import { useCustom, useCustomMutation } from "@refinedev/core";
import type { HttpError } from "@refinedev/core";
import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import type { SystemStatus } from "../../types/api";
import { httpClient } from "../../utils/axios";

interface WafPanelConfig {
  shadow_mode: boolean;
  risk_allow: number;
  risk_challenge: number;
  risk_block: number;
  challenge_type: string;
  honeypot_paths: string[];
  response_filtering: {
    block_stack_traces: boolean;
    json_redact_fields: string[];
  };
  trusted_waf_bypass: { cidrs: string[] };
  rate_limits: {
    default_rps: number;
    burst: number;
    session_expiry_secs: number;
    global_rps: number;
    request_timeout_secs: number;
    fail_open: boolean;
  };
  auto_block: {
    enabled: boolean;
    min_events: number;
    window_secs: number;
  };
}

interface PanelConfigEnvelope {
  config: WafPanelConfig;
  revision: number;
  path: string;
  main_config_file?: string;
}

// ─── Reusable section card ────────────────────────────────────────────────────
const SectionCard: React.FC<{
  icon: React.ReactNode;
  title: React.ReactNode;
  description?: string;
  children: React.ReactNode;
  style?: React.CSSProperties;
}> = ({ icon, title, description, children, style }) => (
  <Card
    style={style}
    styles={{ header: { borderBottom: "1px solid #f0f0f0" } }}
    title={
      <Space>
        {icon}
        <span>{title}</span>
      </Space>
    }
  >
    {description && (
      <Typography.Paragraph type="secondary" style={{ marginBottom: 16 }}>
        {description}
      </Typography.Paragraph>
    )}
    {children}
  </Card>
);

// ─── Switch row (label left, switch right) ────────────────────────────────────
const SwitchRow: React.FC<{ name: string | string[]; label: string; help?: string }> = ({
  name,
  label,
  help,
}) => (
  <Row justify="space-between" align="middle" style={{ padding: "4px 0" }}>
    <Col flex="auto">
      <Space direction="vertical" size={0}>
        <Typography.Text strong>{label}</Typography.Text>
        {help && (
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {help}
          </Typography.Text>
        )}
      </Space>
    </Col>
    <Col flex="none">
      <Form.Item name={name} valuePropName="checked" noStyle>
        <Switch />
      </Form.Item>
    </Col>
  </Row>
);

export const SettingsPage: React.FC = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [form] = Form.useForm<WafPanelConfig>();
  const dirtyRef = useRef(false);
  // Suppress onValuesChange while we apply server data programmatically
  // (some AntD versions still fire onValuesChange on setFieldsValue).
  const suppressDirtyRef = useRef(false);
  const lastRevRef = useRef<number | null>(null);
  const [saving, setSaving] = useState(false);
  const [discarding, setDiscarding] = useState(false);
  const [isDirty, setIsDirty] = useState(false);
  const [panelUnavailable, setPanelUnavailable] = useState<string | null>(null);

  const { result, query } = useCustom<SystemStatus>({
    url: "/api/status",
    method: "get",
    queryOptions: { staleTime: 5_000, refetchInterval: 10_000 },
  });

  const panelQuery = useCustom<PanelConfigEnvelope>({
    url: "/api/panel-config",
    method: "get",
    queryOptions: { staleTime: 3_000, refetchInterval: 15_000, retry: false },
  });

  const { mutate: reload, mutation: reloadMutation } = useCustomMutation();

  const status = result?.data;
  const isLoading = query.isLoading;
  const reloading = reloadMutation.isPending;

  const onReload = () => {
    reload(
      { url: "/api/reload", method: "post", values: {} },
      {
        onSuccess: () => {
          message.success(t("settings.rulesReloaded"));
          void query.refetch();
        },
        onError: (err: HttpError) => message.error(err.message),
      },
    );
  };

  useEffect(() => {
    const err = panelQuery.query.error as { message?: string; statusCode?: number } | undefined;
    if (!err) { setPanelUnavailable(null); return; }
    const msg = err.message ?? "";
    if (err.statusCode === 400 && msg.includes("panel.config_path")) {
      setPanelUnavailable(t("settings.panel.notConfigured"));
    } else {
      setPanelUnavailable(null);
    }
  }, [panelQuery.query.error, t]);

  const envelope = panelQuery.result?.data as PanelConfigEnvelope | undefined;

  const markDirty = () => {
    if (suppressDirtyRef.current) return;
    dirtyRef.current = true;
    setIsDirty(true);
  };
  const markClean = () => {
    dirtyRef.current = false;
    setIsDirty(false);
  };

  // Apply server values to the form while suppressing onValuesChange so the
  // programmatic update doesn't flip the dirty flag. Memoized so it can be
  // referenced from useEffect deps without churn.
  const applyToForm = useCallback(
    (cfg: WafPanelConfig) => {
      suppressDirtyRef.current = true;
      form.setFieldsValue(cfg);
      // reset after AntD's internal change dispatch
      queueMicrotask(() => { suppressDirtyRef.current = false; });
    },
    [form],
  );

  useEffect(() => {
    if (!envelope?.config) return;
    if (lastRevRef.current === null) {
      applyToForm(envelope.config);
      lastRevRef.current = envelope.revision;
      return;
    }
    if (envelope.revision !== lastRevRef.current && !dirtyRef.current) {
      applyToForm(envelope.config);
      lastRevRef.current = envelope.revision;
      message.info(t("settings.panel.syncedFromDisk"));
    }
  }, [envelope, applyToForm, message, t]);

  const onDiscard = async () => {
    setDiscarding(true);
    try {
      // Refetch first so we discard against the most recent disk state, not stale cache.
      const r = await panelQuery.query.refetch();
      // r.data = react-query result wrapper; .data = our API envelope field.
      const fresh = r.data?.data as PanelConfigEnvelope | undefined;
      if (fresh?.config) {
        applyToForm(fresh.config);
        lastRevRef.current = fresh.revision;
      }
      markClean();
    } finally {
      setDiscarding(false);
    }
  };

  const onSavePanel = async () => {
    try {
      const values = await form.validateFields();
      setSaving(true);
      const resp = await httpClient.put<{ success: boolean; data: PanelConfigEnvelope }>(
        "/api/panel-config",
        values,
      );
      message.success(t("settings.panel.saved"));
      markClean();
      const rev = resp.data?.data?.revision;
      if (typeof rev === "number") lastRevRef.current = rev;
      await panelQuery.query.refetch();
    } catch (e: unknown) {
      // AntD validation errors show inline — skip toast
      if (e && typeof e === "object" && "errorFields" in e) return;
      const ax = e as { response?: { data?: { error?: string } }; message?: string };
      const detail = ax.response?.data?.error ?? ax.message ?? String(e);
      message.error(detail);
      // dirtyRef intentionally NOT reset on API error so user can retry;
      // they can use Discard to re-sync from disk if needed.
    } finally {
      setSaving(false);
    }
  };

  const riskAllow = Form.useWatch("risk_allow", form) ?? envelope?.config?.risk_allow ?? 51;
  const riskChallenge = Form.useWatch("risk_challenge", form) ?? envelope?.config?.risk_challenge ?? 74;
  const riskBlock = Form.useWatch("risk_block", form) ?? envelope?.config?.risk_block ?? 75;

  // Cross-field revalidate when sliders change so the InputNumber/risk_block
  // shows its error immediately (without waiting for submit).
  useEffect(() => {
    if (form.isFieldTouched("risk_block")) {
      form.validateFields(["risk_block"]).catch(() => {});
    }
    if (form.isFieldTouched("risk_challenge")) {
      form.validateFields(["risk_challenge"]).catch(() => {});
    }
  }, [riskAllow, riskChallenge, form]);

  const ipsCount = (status?.rules?.allow_ips ?? 0) + (status?.rules?.block_ips ?? 0);
  const urlsCount = (status?.rules?.allow_urls ?? 0) + (status?.rules?.block_urls ?? 0);

  const formDisabled = panelQuery.query.isLoading && !envelope;

  return (
    <Form<WafPanelConfig>
      form={form}
      layout="vertical"
      disabled={formDisabled}
      onValuesChange={markDirty}
    >
      <Space direction="vertical" size="middle" style={{ width: "100%" }}>

        {/* ── System Status ──────────────────────────────────────────── */}
        <Card
          title={
            <Space>
              <SecurityScanOutlined />
              {t("settings.systemStatus")}
            </Space>
          }
          extra={
            <Space>
              <Button icon={<ReloadOutlined />} onClick={() => void query.refetch()} loading={isLoading}>
                {t("common.refresh")}
              </Button>
              <Button type="primary" icon={<ThunderboltOutlined />} onClick={onReload} loading={reloading}>
                {t("settings.reloadRules")}
              </Button>
            </Space>
          }
          loading={isLoading && !status}
        >
          <Descriptions column={{ xs: 1, sm: 2, lg: 4 }} size="small">
            <Descriptions.Item label={t("settings.version")}>
              <Tag color="blue">{status?.version ?? "—"}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label={t("settings.activeHosts")}>
              <Badge count={status?.hosts ?? 0} showZero color="#1677ff" />
            </Descriptions.Item>
            <Descriptions.Item label={t("settings.totalRequests")}>
              {status?.total_requests?.toLocaleString() ?? "0"}
            </Descriptions.Item>
            <Descriptions.Item label={t("settings.rules")}>
              IPs: {ipsCount} / URLs: {urlsCount}
            </Descriptions.Item>
          </Descriptions>
        </Card>

        {/* ── Panel config file info + Save ──────────────────────────── */}
        {panelUnavailable ? (
          <Alert type="warning" message={panelUnavailable} showIcon />
        ) : (
          <>
            <Card
              size="small"
              style={{ background: "#fafafa" }}
              styles={{ body: { padding: "8px 16px" } }}
            >
              <Row justify="space-between" align="middle" wrap>
                <Col>
                  <Space wrap size={4}>
                    <CheckCircleOutlined style={{ color: "#52c41a" }} />
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      {t("settings.panel.fileLabel")}:
                    </Typography.Text>
                    <Typography.Text code style={{ fontSize: 12 }}>
                      {envelope?.path ?? "—"}
                    </Typography.Text>
                    {envelope?.main_config_file && (
                      <>
                        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                          {" "}← {t("settings.panel.mainConfigLabel")}:
                        </Typography.Text>
                        <Typography.Text code style={{ fontSize: 12 }}>
                          {envelope.main_config_file}
                        </Typography.Text>
                      </>
                    )}
                    {envelope?.revision ? (
                      <Tooltip title={t("settings.panel.revisionLabel")}>
                        <Tag style={{ fontSize: 11 }}>mtime {envelope.revision}</Tag>
                      </Tooltip>
                    ) : null}
                  </Space>
                </Col>
                <Col>
                  <Space>
                    <Button
                      size="small"
                      icon={<ReloadOutlined />}
                      onClick={() => void panelQuery.query.refetch()}
                      loading={panelQuery.query.isFetching}
                    >
                      {t("common.refresh")}
                    </Button>
                    {isDirty && (
                      <Button
                        size="small"
                        onClick={() => void onDiscard()}
                        loading={discarding}
                        disabled={saving}
                      >
                        {t("settings.panel.discard")}
                      </Button>
                    )}
                    <Button
                      type="primary"
                      size="small"
                      icon={<SaveOutlined />}
                      loading={saving}
                      disabled={discarding}
                      onClick={() => void onSavePanel()}
                    >
                      {t("common.save")}
                    </Button>
                  </Space>
                </Col>
              </Row>
            </Card>

            {/* ── Shadow Mode ──────────────────────────────────────────── */}
            <SectionCard
              icon={<ExperimentOutlined style={{ color: "#fa8c16" }} />}
              title={t("settings.panel.shadowMode")}
            >
              <SwitchRow
                name="shadow_mode"
                label={t("settings.panel.shadowModeLabel")}
                help={t("settings.panel.shadowModeHelp")}
              />
            </SectionCard>

            {/* ── Risk Thresholds ──────────────────────────────────────── */}
            <SectionCard
              icon={<SecurityScanOutlined style={{ color: "#1677ff" }} />}
              title={t("settings.panel.riskThresholds")}
            >
              <Form.Item
                name="risk_allow"
                label={
                  <Row style={{ width: "100%" }} justify="space-between">
                    <span style={{ color: "#52c41a", fontWeight: 600 }}>
                      {t("settings.panel.allowBandShort")} (0 – {riskAllow})
                    </span>
                    <span style={{ fontVariantNumeric: "tabular-nums" }}>{riskAllow}</span>
                  </Row>
                }
                rules={[{ required: true, type: "number", min: 0, max: 98 }]}
              >
                <Slider min={0} max={98} tooltip={{ open: false }} styles={{ track: { background: "#52c41a" } }} />
              </Form.Item>

              <Form.Item
                name="risk_challenge"
                label={
                  <Row style={{ width: "100%" }} justify="space-between">
                    <span style={{ color: "#fa8c16", fontWeight: 600 }}>
                      {t("settings.panel.challengeBandShort")} ({riskAllow + 1} – {riskChallenge})
                    </span>
                    <span style={{ fontVariantNumeric: "tabular-nums" }}>{riskChallenge}</span>
                  </Row>
                }
                dependencies={["risk_allow"]}
                rules={[
                  { required: true, type: "number" },
                  {
                    validator: async (_, v) => {
                      const a = form.getFieldValue("risk_allow") as number;
                      if (typeof v === "number" && v > a) return;
                      return Promise.reject(new Error(t("settings.panel.riskOrderError")));
                    },
                  },
                ]}
              >
                <Slider min={1} max={99} tooltip={{ open: false }} styles={{ track: { background: "#fa8c16" } }} />
              </Form.Item>

              <Row align="middle" style={{ marginTop: 4 }}>
                <Typography.Text type="secondary">
                  {t("settings.panel.blockThresholdLabel")}:{" "}
                </Typography.Text>
                <Tag color="red" style={{ marginLeft: 8, fontWeight: 600 }}>
                  &gt;= {riskBlock}
                </Tag>
                <Form.Item
                  name="risk_block"
                  noStyle
                  dependencies={["risk_challenge"]}
                  rules={[
                    { required: true, type: "number" },
                    {
                      validator: async (_, v) => {
                        const c = form.getFieldValue("risk_challenge") as number;
                        if (typeof v === "number" && v > c) return;
                        return Promise.reject(new Error(t("settings.panel.riskOrderError")));
                      },
                    },
                  ]}
                >
                  <InputNumber min={2} max={100} size="small" style={{ width: 80, marginLeft: 12 }} />
                </Form.Item>
              </Row>
            </SectionCard>

            {/* ── Challenge Engine ─────────────────────────────────────── */}
            <SectionCard
              icon={<SafetyCertificateOutlined style={{ color: "#1677ff" }} />}
              title={t("settings.panel.challengeEngine")}
            >
              <Form.Item name="challenge_type" label={t("settings.panel.challengeType")} style={{ marginBottom: 0 }}>
                <Select
                  style={{ width: 240 }}
                  options={[
                    { value: "js_challenge", label: t("settings.panel.challengeJs") },
                    { value: "captcha", label: t("settings.panel.challengeCaptcha") },
                    { value: "proof_of_work", label: t("settings.panel.challengePow") },
                  ]}
                />
              </Form.Item>
            </SectionCard>

            {/* ── Honeypot Paths ────────────────────────────────────────── */}
            <SectionCard
              icon={<BugOutlined style={{ color: "#722ed1" }} />}
              title={t("settings.panel.honeypotPaths")}
              description={t("settings.panel.honeypotPathsHelp")}
            >
              <Form.Item name="honeypot_paths" style={{ marginBottom: 0 }}>
                <Select
                  mode="tags"
                  style={{ width: "100%" }}
                  tokenSeparators={[","]}
                  placeholder="/trap-path"
                  suffixIcon={null}
                />
              </Form.Item>
            </SectionCard>

            {/* ── Response Filtering ────────────────────────────────────── */}
            <SectionCard
              icon={<SecurityScanOutlined style={{ color: "#1677ff" }} />}
              title={t("settings.panel.responseFiltering")}
            >
              <SwitchRow
                name={["response_filtering", "block_stack_traces"]}
                label={t("settings.panel.blockStackTraces")}
              />
              <Form.Item
                name={["response_filtering", "json_redact_fields"]}
                label={t("settings.panel.redactJsonFields")}
                style={{ marginTop: 16, marginBottom: 0 }}
              >
                <Select
                  mode="tags"
                  style={{ width: "100%" }}
                  placeholder="field_name"
                  tokenSeparators={[","]}
                  suffixIcon={null}
                />
              </Form.Item>
            </SectionCard>

            {/* ── Trusted IPs / CIDRs ───────────────────────────────────── */}
            <SectionCard
              icon={<GlobalOutlined style={{ color: "#52c41a" }} />}
              title={t("settings.panel.trustedBypass")}
              description={t("settings.panel.trustedBypassHelp")}
            >
              <Form.Item name={["trusted_waf_bypass", "cidrs"]} style={{ marginBottom: 0 }}>
                <Select
                  mode="tags"
                  style={{ width: "100%" }}
                  placeholder="1.2.3.4/32 or 10.0.0.0/8"
                  tokenSeparators={[","]}
                  suffixIcon={null}
                />
              </Form.Item>
            </SectionCard>

            {/* ── Rate Limits & Session ─────────────────────────────────── */}
            <SectionCard
              icon={<ThunderboltOutlined style={{ color: "#fa8c16" }} />}
              title={t("settings.panel.rateLimits")}
            >
              <Row gutter={[16, 0]}>
                <Col xs={24} sm={12}>
                  <Form.Item name={["rate_limits", "default_rps"]} label={t("settings.panel.defaultRps")}>
                    <InputNumber min={0} style={{ width: "100%" }} addonAfter="req/s" />
                  </Form.Item>
                </Col>
                <Col xs={24} sm={12}>
                  <Form.Item name={["rate_limits", "burst"]} label={t("settings.panel.burst")}>
                    <InputNumber min={0} style={{ width: "100%" }} addonAfter="req/s" />
                  </Form.Item>
                </Col>
                <Col xs={24} sm={12}>
                  <Form.Item name={["rate_limits", "session_expiry_secs"]} label={t("settings.panel.sessionExpiry")}>
                    <InputNumber min={0} style={{ width: "100%" }} addonAfter="s" />
                  </Form.Item>
                </Col>
                <Col xs={24} sm={12}>
                  <Form.Item name={["rate_limits", "global_rps"]} label={t("settings.panel.globalRps")} extra={t("settings.panel.zeroOff")}>
                    <InputNumber min={0} style={{ width: "100%" }} addonAfter="req/s" />
                  </Form.Item>
                </Col>
                <Col xs={24} sm={12}>
                  <Form.Item name={["rate_limits", "request_timeout_secs"]} label={t("settings.panel.requestTimeout")} extra={t("settings.panel.zeroOff")}>
                    <InputNumber min={0} style={{ width: "100%" }} addonAfter="s" />
                  </Form.Item>
                </Col>
                <Col xs={24} sm={12} style={{ display: "flex", alignItems: "flex-end", paddingBottom: 24 }}>
                  <SwitchRow
                    name={["rate_limits", "fail_open"]}
                    label={t("settings.panel.failOpen")}
                    help={t("settings.panel.failOpenHelp")}
                  />
                </Col>
              </Row>
            </SectionCard>

            {/* ── Auto-Block ────────────────────────────────────────────── */}
            <SectionCard
              icon={<SecurityScanOutlined style={{ color: "#ff4d4f" }} />}
              title={t("settings.panel.autoBlock")}
            >
              <SwitchRow name={["auto_block", "enabled"]} label={t("common.enabled")} />
              <Row gutter={[16, 0]} style={{ marginTop: 16 }}>
                <Col xs={24} sm={12}>
                  <Form.Item name={["auto_block", "min_events"]} label={t("settings.panel.autoBlockMinEvents")}>
                    <InputNumber min={1} style={{ width: "100%" }} />
                  </Form.Item>
                </Col>
                <Col xs={24} sm={12}>
                  <Form.Item name={["auto_block", "window_secs"]} label={t("settings.panel.autoBlockWindow")}>
                    <InputNumber min={1} style={{ width: "100%" }} addonAfter="s" />
                  </Form.Item>
                </Col>
              </Row>
            </SectionCard>

            {/* ── Bottom save shortcut ─────────────────────────────────── */}
            <Row justify="end">
              <Space>
                {isDirty && (
                  <Button
                    onClick={() => void onDiscard()}
                    loading={discarding}
                    disabled={saving}
                  >
                    {t("settings.panel.discard")}
                  </Button>
                )}
                <Button
                  type="primary"
                  icon={<SaveOutlined />}
                  loading={saving}
                  disabled={discarding}
                  onClick={() => void onSavePanel()}
                >
                  {t("common.save")}
                </Button>
              </Space>
            </Row>
          </>
        )}

        {/* ── API Connection Info ───────────────────────────────────── */}
        <Card title={t("settings.configuration")} size="small">
          <Space direction="vertical" size={4} style={{ width: "100%" }}>
            <Typography.Text type="secondary">
              API: <Typography.Text code>http://&lt;host&gt;:9527</Typography.Text>
            </Typography.Text>
            <Typography.Text type="secondary">
              WS events: <Typography.Text code>ws://&lt;host&gt;:9527/ws/events</Typography.Text>
            </Typography.Text>
            <Typography.Text type="secondary">
              WS logs: <Typography.Text code>ws://&lt;host&gt;:9527/ws/logs</Typography.Text>
            </Typography.Text>
          </Space>
        </Card>

      </Space>
    </Form>
  );
};
