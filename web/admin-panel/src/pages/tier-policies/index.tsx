import {
  Alert,
  Button,
  Card,
  Col,
  Drawer,
  Form,
  Input,
  InputNumber,
  Radio,
  Row,
  Select,
  Slider,
  Space,
  Table,
  Tag,
  Typography,
  App,
  Popconfirm,
} from "antd";
import {
  ReloadOutlined,
  SaveOutlined,
  PlusOutlined,
  DeleteOutlined,
  ThunderboltOutlined,
  PlayCircleOutlined,
} from "@ant-design/icons";
import { useCustom, useCustomMutation } from "@refinedev/core";
import type { ColumnsType } from "antd/es/table";
import { useTranslation } from "react-i18next";
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";

// ── Types ──────────────────────────────────────────────────────────────────────

interface TierPolicy {
  fail_mode: "close" | "open";
  ddos_threshold_rps: number;
  cache_policy: "no_cache" | "short_ttl" | "aggressive" | "default";
  risk_thresholds: { allow: number; challenge: number; block: number };
}

interface ClassifierRule {
  id: number;
  priority: number;
  tier: string;
  host_match?: string;
  path_match?: string;
  methods?: string[];
}

interface TierConfig {
  policies: {
    critical: TierPolicy;
    high: TierPolicy;
    medium: TierPolicy;
    catch_all: TierPolicy;
  };
  classifier_rules: ClassifierRule[];
}

interface DryRunResponse {
  matched_tier: string;
  matched_rule_id?: number;
}

// ── Constants ──────────────────────────────────────────────────────────────────

const DEFAULT_POLICY: TierPolicy = {
  fail_mode: "close",
  ddos_threshold_rps: 100,
  cache_policy: "default",
  risk_thresholds: { allow: 20, challenge: 60, block: 85 },
};

const DEFAULT_CONFIG: TierConfig = {
  policies: {
    critical: { ...DEFAULT_POLICY, ddos_threshold_rps: 50, cache_policy: "no_cache" },
    high: { ...DEFAULT_POLICY, ddos_threshold_rps: 200 },
    medium: { ...DEFAULT_POLICY, ddos_threshold_rps: 500, cache_policy: "short_ttl" },
    catch_all: { ...DEFAULT_POLICY, fail_mode: "open", ddos_threshold_rps: 1000, cache_policy: "aggressive" },
  },
  classifier_rules: [],
};

const TIER_KEYS = ["critical", "high", "medium", "catch_all"] as const;
type TierKey = (typeof TIER_KEYS)[number];

const TIER_COLOR: Record<TierKey, string> = {
  critical: "#f5222d",
  high: "#fa8c16",
  medium: "#fadb14",
  catch_all: "#1677ff",
};

const HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

// Stable tooltip config — defined outside component to avoid new object on every render.
const SLIDER_TOOLTIP = { formatter: (v?: number) => `${v ?? 0}` };

// ── SectionCard helper ─────────────────────────────────────────────────────────

interface SectionCardProps {
  icon: React.ReactNode;
  title: string;
  extra?: React.ReactNode;
  children: React.ReactNode;
}

const SectionCard: React.FC<SectionCardProps> = ({ icon, title, extra, children }) => (
  <Card
    size="small"
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

// ── TierPolicyCard ─────────────────────────────────────────────────────────────

interface TierPolicyCardProps {
  tierKey: TierKey;
  label: string;
  policy: TierPolicy;
  onChange: (p: TierPolicy) => void;
  t: (key: string) => string;
}

const TierPolicyCard: React.FC<TierPolicyCardProps> = React.memo(({ tierKey, label, policy: policyProp, onChange, t }) => {
  const policy = policyProp ?? DEFAULT_POLICY;
  const color = TIER_COLOR[tierKey];

  // Local threshold state: slider drags only update local state (no parent re-render).
  // Parent is notified via onAfterChange (mouse-up / keyboard-end), which is ~100x
  // less frequent than onChange during a drag. This eliminates the cascade where
  // 60+ setConfig calls per second caused the parent to re-render on every pixel.
  const [localThresh, setLocalThresh] = useState(
    () => policy.risk_thresholds ?? { allow: 20, challenge: 60, block: 85 },
  );

  // Keep stable refs so the stable callbacks below always read latest values.
  const onChangeRef = useRef(onChange);
  const policyRef = useRef(policy);
  const localThreshRef = useRef(localThresh);
  onChangeRef.current = onChange;
  policyRef.current = policy;
  localThreshRef.current = localThresh;

  // Sync local thresh when parent policy changes from outside (API load, config
  // reset). We compare values so we don't clobber a mid-drag local state with the
  // echo of our own last commit.
  useEffect(() => {
    const incoming = policy.risk_thresholds ?? { allow: 20, challenge: 60, block: 85 };
    const cur = localThreshRef.current;
    if (
      incoming.allow !== cur.allow ||
      incoming.challenge !== cur.challenge ||
      incoming.block !== cur.block
    ) {
      setLocalThresh(incoming);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [policy.risk_thresholds]);

  // For non-slider fields: direct parent update (lightweight, no drag).
  const setField = useCallback(<K extends keyof TierPolicy>(key: K, val: TierPolicy[K]) =>
    onChangeRef.current({ ...policyRef.current, [key]: val }), []);

  // During drag: update local state only (fast — no parent involved).
  const onSliderChange = useCallback((field: "allow" | "challenge" | "block", val: number) => {
    setLocalThresh((prev) => ({ ...prev, [field]: val }));
  }, []);

  // On drag end: commit final value to parent.
  const onSliderCommit = useCallback((field: "allow" | "challenge" | "block", val: number) => {
    setLocalThresh((prev) => {
      const next = { ...prev, [field]: val };
      onChangeRef.current({ ...policyRef.current, risk_thresholds: next });
      return next;
    });
  }, []);

  const { allow, challenge, block } = localThresh;
  const thresholdsValid = allow < challenge && challenge < block;

  return (
    <Card
      size="small"
      title={<Tag color={color} style={{ fontWeight: 600 }}>{label.toUpperCase()}</Tag>}
      style={{ height: "100%" }}
    >
      <Form layout="vertical" size="small">
        <Form.Item label={t("tierPolicies.failMode")}>
          <Radio.Group
            value={policy.fail_mode}
            onChange={(e) => setField("fail_mode", e.target.value)}
          >
            <Radio value="close">{t("tierPolicies.failClose")}</Radio>
            <Radio value="open">{t("tierPolicies.failOpen")}</Radio>
          </Radio.Group>
        </Form.Item>

        <Form.Item label={t("tierPolicies.ddosThreshold")}>
          <InputNumber
            min={1}
            max={100000}
            value={policy.ddos_threshold_rps}
            onChange={(v) => v !== null && setField("ddos_threshold_rps", v)}
            addonAfter="rps"
            style={{ width: "100%" }}
          />
        </Form.Item>

        <Form.Item label={t("tierPolicies.cachePolicy")}>
          <Select
            value={policy.cache_policy}
            onChange={(v) => setField("cache_policy", v)}
            style={{ width: "100%" }}
            options={[
              { value: "no_cache", label: t("tierPolicies.cacheNoCache") },
              { value: "short_ttl", label: t("tierPolicies.cacheShortTtl") },
              { value: "aggressive", label: t("tierPolicies.cacheAggressive") },
              { value: "default", label: t("tierPolicies.cacheDefault") },
            ]}
          />
        </Form.Item>

        <Form.Item
          label={t("tierPolicies.riskThresholds")}
          validateStatus={thresholdsValid ? "" : "error"}
          help={thresholdsValid ? undefined : t("tierPolicies.thresholdError")}
        >
          <Space direction="vertical" style={{ width: "100%" }} size={2}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <Tag color="green" style={{ width: 70, textAlign: "center" }}>
                {t("tierPolicies.allow")}
              </Tag>
              <Slider
                min={0}
                max={100}
                value={allow}
                onChange={(v) => onSliderChange("allow", v)}
                onAfterChange={(v) => onSliderCommit("allow", v)}
                style={{ flex: 1 }}
                tooltip={SLIDER_TOOLTIP}
              />
              <span style={{ width: 28, textAlign: "right", fontSize: 12 }}>{allow}</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <Tag color="orange" style={{ width: 70, textAlign: "center" }}>
                {t("tierPolicies.challenge")}
              </Tag>
              <Slider
                min={0}
                max={100}
                value={challenge}
                onChange={(v) => onSliderChange("challenge", v)}
                onAfterChange={(v) => onSliderCommit("challenge", v)}
                style={{ flex: 1 }}
                tooltip={SLIDER_TOOLTIP}
              />
              <span style={{ width: 28, textAlign: "right", fontSize: 12 }}>{challenge}</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <Tag color="red" style={{ width: 70, textAlign: "center" }}>
                {t("tierPolicies.block")}
              </Tag>
              <Slider
                min={0}
                max={100}
                value={block}
                onChange={(v) => onSliderChange("block", v)}
                onAfterChange={(v) => onSliderCommit("block", v)}
                style={{ flex: 1 }}
                tooltip={SLIDER_TOOLTIP}
              />
              <span style={{ width: 28, textAlign: "right", fontSize: 12 }}>{block}</span>
            </div>
          </Space>
        </Form.Item>
      </Form>
    </Card>
  );
});

// ── Page ───────────────────────────────────────────────────────────────────────

export const TierPoliciesPage: React.FC = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();

  const [config, setConfig] = useState<TierConfig>(DEFAULT_CONFIG);
  const [endpointMissing, setEndpointMissing] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [testMethod, setTestMethod] = useState("GET");
  const [testHost, setTestHost] = useState("");
  const [testPath, setTestPath] = useState("/");
  const [testResult, setTestResult] = useState<DryRunResponse | null>(null);

  const isDirty = useRef(false);
  const [form] = Form.useForm<Omit<ClassifierRule, "id">>();

  // ── Load config ──────────────────────────────────────────────────────────────

  const { result: loadResult, query: loadQuery } = useCustom<TierConfig>({
    url: "/api/tier-policies",
    method: "get",
    queryOptions: { retry: false },
    errorNotification: false,
  });

  useEffect(() => {
    if (loadResult?.data) {
      const raw = loadResult.data;
      const cfg = (raw as { data?: TierConfig }).data ?? (raw as TierConfig);
      const policies = (cfg as TierConfig | undefined)?.policies;
      if (
        policies &&
        typeof policies === "object" &&
        "critical" in policies &&
        "high" in policies
      ) {
        setConfig({
          policies: {
            critical: policies.critical ?? DEFAULT_POLICY,
            high: policies.high ?? DEFAULT_POLICY,
            medium: policies.medium ?? DEFAULT_POLICY,
            catch_all: policies.catch_all ?? DEFAULT_POLICY,
          },
          classifier_rules: (cfg as TierConfig).classifier_rules ?? [],
        });
        setEndpointMissing(false);
        isDirty.current = false;
      }
    }
  }, [loadResult]);

  useEffect(() => {
    if (loadQuery.isError) {
      setEndpointMissing(true);
    }
  }, [loadQuery.isError]);

  // ── Save ─────────────────────────────────────────────────────────────────────

  const { mutate: saveConfig, mutation: saveMutation } = useCustomMutation();
  const saving = saveMutation.isPending;

  const onSave = () => {
    saveConfig(
      { url: "/api/tier-policies", method: "put", values: config },
      {
        onSuccess: () => {
          message.success(t("tierPolicies.saved"));
          isDirty.current = false;
        },
        onError: (err) => message.error(err.message),
      },
    );
  };

  // ── Dry-run test ─────────────────────────────────────────────────────────────

  const { mutate: runDryRun, mutation: dryRunMutation } = useCustomMutation();
  const dryRunning = dryRunMutation.isPending;

  const onDryRun = () => {
    runDryRun(
      {
        url: "/api/tier-policies/dry-run",
        method: "post",
        values: { method: testMethod, host: testHost, path: testPath },
      },
      {
        onSuccess: (data) => {
          const res = data?.data as DryRunResponse | undefined;
          setTestResult(res ?? { matched_tier: "unknown" });
        },
        onError: () => setTestResult({ matched_tier: t("tierPolicies.dryRunError") }),
      },
    );
  };

  // ── Policy change helpers ────────────────────────────────────────────────────

  const onPolicyChange = useCallback((key: TierKey, p: TierPolicy) => {
    isDirty.current = true;
    setConfig((prev) => ({ ...prev, policies: { ...prev.policies, [key]: p } }));
  }, []);

  // Pre-create stable per-tier handlers so React.memo on TierPolicyCard works correctly:
  // only the card whose policy actually changed will re-render.
  const policyHandlers = useMemo<Record<TierKey, (p: TierPolicy) => void>>(
    () => ({
      critical: (p) => onPolicyChange("critical", p),
      high: (p) => onPolicyChange("high", p),
      medium: (p) => onPolicyChange("medium", p),
      catch_all: (p) => onPolicyChange("catch_all", p),
    }),
    [onPolicyChange],
  );

  // ── Classifier rules ─────────────────────────────────────────────────────────

  const onAddRule = async () => {
    const values = await form.validateFields();
    const newRule: ClassifierRule = {
      id: Date.now(),
      ...values,
    };
    isDirty.current = true;
    setConfig((prev) => ({
      ...prev,
      classifier_rules: [...prev.classifier_rules, newRule],
    }));
    form.resetFields();
    setDrawerOpen(false);
  };

  const onDeleteRule = (id: number) => {
    isDirty.current = true;
    setConfig((prev) => ({
      ...prev,
      classifier_rules: prev.classifier_rules.filter((r) => r.id !== id),
    }));
  };

  const ruleColumns: ColumnsType<ClassifierRule> = [
    {
      title: t("tierPolicies.priority"),
      dataIndex: "priority",
      width: 80,
      sorter: (a, b) => a.priority - b.priority,
    },
    {
      title: t("tierPolicies.tier"),
      dataIndex: "tier",
      width: 100,
      render: (v: string) => {
        const color = TIER_COLOR[v as TierKey] ?? "default";
        return <Tag color={color}>{v}</Tag>;
      },
    },
    {
      title: t("tierPolicies.hostMatch"),
      dataIndex: "host_match",
      ellipsis: true,
      render: (v?: string) =>
        v ? (
          <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>{v}</span>
        ) : (
          <span style={{ color: "#bfbfbf" }}>*</span>
        ),
    },
    {
      title: t("tierPolicies.pathMatch"),
      dataIndex: "path_match",
      ellipsis: true,
      render: (v?: string) =>
        v ? (
          <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>{v}</span>
        ) : (
          <span style={{ color: "#bfbfbf" }}>*</span>
        ),
    },
    {
      title: t("tierPolicies.methods"),
      dataIndex: "methods",
      width: 180,
      render: (v?: string[]) =>
        v?.length
          ? v.map((m) => (
              <Tag key={m} style={{ fontSize: 11 }}>
                {m}
              </Tag>
            ))
          : <span style={{ color: "#bfbfbf" }}>{t("tierPolicies.allMethods")}</span>,
    },
    {
      title: "",
      key: "actions",
      width: 60,
      render: (_: unknown, r: ClassifierRule) => (
        <Popconfirm title={t("common.confirm")} onConfirm={() => onDeleteRule(r.id)}>
          <Button size="small" type="text" icon={<DeleteOutlined />} danger />
        </Popconfirm>
      ),
    },
  ];

  const TIER_LABELS: Record<TierKey, string> = {
    critical: t("tierPolicies.tierCritical"),
    high: t("tierPolicies.tierHigh"),
    medium: t("tierPolicies.tierMedium"),
    catch_all: t("tierPolicies.tierCatchAll"),
  };

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      {/* Header */}
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <div>
          <Typography.Title level={4} style={{ margin: 0 }}>
            {t("tierPolicies.title")}
          </Typography.Title>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {t("tierPolicies.subtitle")}
          </Typography.Text>
        </div>
        <Space>
          <Button
            icon={<ReloadOutlined spin={loadQuery.isLoading} />}
            onClick={() => loadQuery.refetch()}
            disabled={endpointMissing}
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
          message={t("tierPolicies.endpointMissing")}
          description={t("tierPolicies.endpointMissingDesc")}
        />
      )}

      {/* Per-tier policy grid */}
      <SectionCard
        icon={<ThunderboltOutlined style={{ color: "#1677ff" }} />}
        title={t("tierPolicies.perTierPolicies")}
      >
        <Row gutter={[12, 12]}>
          {TIER_KEYS.map((key) => (
            <Col key={key} xs={24} sm={12} xl={6}>
              <TierPolicyCard
                tierKey={key}
                label={TIER_LABELS[key]}
                policy={config?.policies?.[key] ?? DEFAULT_POLICY}
                onChange={policyHandlers[key]}
                t={t}
              />
            </Col>
          ))}
        </Row>
      </SectionCard>

      {/* Classifier rules table */}
      <SectionCard
        icon={<ThunderboltOutlined style={{ color: "#722ed1" }} />}
        title={t("tierPolicies.classifierRules")}
        extra={
          <Button
            size="small"
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => setDrawerOpen(true)}
          >
            {t("tierPolicies.addRule")}
          </Button>
        }
      >
        <Table<ClassifierRule>
          rowKey="id"
          size="small"
          dataSource={config.classifier_rules}
          columns={ruleColumns}
          pagination={false}
          locale={{ emptyText: t("tierPolicies.noRules") }}
          scroll={{ x: 700 }}
        />
      </SectionCard>

      {/* Test classifier */}
      <SectionCard
        icon={<PlayCircleOutlined style={{ color: "#13c2c2" }} />}
        title={t("tierPolicies.testClassifier")}
      >
        <Space wrap>
          <Select
            value={testMethod}
            onChange={setTestMethod}
            style={{ width: 100 }}
            options={HTTP_METHODS.map((m) => ({ value: m, label: m }))}
          />
          <Input
            placeholder={t("tierPolicies.testHost")}
            value={testHost}
            onChange={(e) => setTestHost(e.target.value)}
            style={{ width: 220 }}
          />
          <Input
            placeholder={t("tierPolicies.testPath")}
            value={testPath}
            onChange={(e) => setTestPath(e.target.value)}
            style={{ width: 220 }}
          />
          <Button
            type="primary"
            icon={<PlayCircleOutlined />}
            loading={dryRunning}
            onClick={onDryRun}
            disabled={endpointMissing}
          >
            {t("tierPolicies.run")}
          </Button>
        </Space>
        {testResult && (
          <div style={{ marginTop: 12 }}>
            <Alert
              type="info"
              showIcon
              message={
                <Space>
                  <span>{t("tierPolicies.matchedTier")}:</span>
                  <Tag color={TIER_COLOR[testResult.matched_tier as TierKey] ?? "default"}>
                    {testResult.matched_tier}
                  </Tag>
                  {testResult.matched_rule_id !== undefined && (
                    <span style={{ color: "#8c8c8c", fontSize: 12 }}>
                      {t("tierPolicies.ruleId")}: #{testResult.matched_rule_id}
                    </span>
                  )}
                </Space>
              }
            />
          </div>
        )}
      </SectionCard>

      {/* Add classifier rule drawer */}
      <Drawer
        title={t("tierPolicies.addRuleTitle")}
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        width={480}
        extra={
          <Button type="primary" onClick={onAddRule}>
            {t("common.add")}
          </Button>
        }
        destroyOnClose
      >
        <Form form={form} layout="vertical" initialValues={{ priority: 100, tier: "medium" }}>
          <Form.Item name="priority" label={t("tierPolicies.priority")} rules={[{ required: true }]}>
            <InputNumber min={1} max={9999} style={{ width: "100%" }} />
          </Form.Item>
          <Form.Item name="tier" label={t("tierPolicies.tier")} rules={[{ required: true }]}>
            <Select
              options={TIER_KEYS.map((k) => ({ value: k, label: TIER_LABELS[k] }))}
            />
          </Form.Item>
          <Form.Item name="host_match" label={t("tierPolicies.hostMatch")}>
            <Input placeholder="example.com" style={{ fontFamily: "ui-monospace, monospace" }} />
          </Form.Item>
          <Form.Item name="path_match" label={t("tierPolicies.pathMatch")}>
            <Input placeholder="/api/*" style={{ fontFamily: "ui-monospace, monospace" }} />
          </Form.Item>
          <Form.Item name="methods" label={t("tierPolicies.methods")}>
            <Select
              mode="multiple"
              options={HTTP_METHODS.map((m) => ({ value: m, label: m }))}
              placeholder={t("tierPolicies.allMethods")}
            />
          </Form.Item>
        </Form>
      </Drawer>
    </Space>
  );
};
