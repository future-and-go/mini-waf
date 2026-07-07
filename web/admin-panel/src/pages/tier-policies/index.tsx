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
  Tooltip,
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

// ── Types (mirror waf_common::tier serde shapes exactly) ──────────────────────

type CacheMode = "no_cache" | "short_ttl" | "aggressive" | "default";

/** Tagged enum: `no_cache` carries no TTL, every other mode requires one. */
interface CachePolicy {
  mode: CacheMode;
  ttl_seconds?: number;
}

interface TierPolicy {
  fail_mode: "close" | "open";
  ddos_threshold_rps: number;
  cache_policy: CachePolicy;
  risk_thresholds: { allow: number; challenge: number; block: number };
}

type PathMatchKind = "exact" | "prefix" | "regex";
type HostMatchKind = "exact" | "suffix" | "regex";

interface PathMatch {
  kind: PathMatchKind;
  value: string;
}

interface HostMatch {
  kind: HostMatchKind;
  value: string;
}

interface HeaderMatch {
  name: string;
  value: string;
}

interface ClassifierRule {
  priority: number;
  tier: TierKey;
  host?: HostMatch | null;
  path?: PathMatch | null;
  method?: string[] | null;
  headers?: HeaderMatch[] | null;
}

interface TierConfig {
  default_tier: TierKey;
  classifier_rules: ClassifierRule[];
  policies: Record<TierKey, TierPolicy>;
}

interface DryRunResponse {
  matched_tier: string;
  policy?: TierPolicy | null;
}

// ── Constants ──────────────────────────────────────────────────────────────────

const TIER_KEYS = ["critical", "high", "medium", "catch_all"] as const;
type TierKey = (typeof TIER_KEYS)[number];

// Suggested TTL per cache mode when the operator switches away from no_cache;
// values follow the shipped configs/tier-protection.toml.
const DEFAULT_TTL: Record<Exclude<CacheMode, "no_cache">, number> = {
  short_ttl: 5,
  default: 30,
  aggressive: 300,
};

const DEFAULT_POLICY: TierPolicy = {
  fail_mode: "open",
  ddos_threshold_rps: 1000,
  cache_policy: { mode: "no_cache" },
  risk_thresholds: { allow: 30, challenge: 70, block: 90 },
};

// Mirrors configs/tier-protection.toml so the pre-load render matches what a
// fresh install actually enforces.
const DEFAULT_CONFIG: TierConfig = {
  default_tier: "catch_all",
  classifier_rules: [
    { priority: 100, tier: "critical", path: { kind: "prefix", value: "/critical" } },
    { priority: 90, tier: "high", path: { kind: "prefix", value: "/high" } },
    { priority: 80, tier: "medium", path: { kind: "prefix", value: "/medium" } },
  ],
  policies: {
    critical: {
      fail_mode: "close",
      ddos_threshold_rps: 50,
      cache_policy: { mode: "no_cache" },
      risk_thresholds: { allow: 20, challenge: 50, block: 70 },
    },
    high: {
      fail_mode: "close",
      ddos_threshold_rps: 200,
      cache_policy: { mode: "short_ttl", ttl_seconds: 5 },
      risk_thresholds: { allow: 30, challenge: 60, block: 80 },
    },
    medium: {
      fail_mode: "open",
      ddos_threshold_rps: 1000,
      cache_policy: { mode: "default", ttl_seconds: 30 },
      risk_thresholds: { allow: 40, challenge: 70, block: 90 },
    },
    catch_all: {
      fail_mode: "open",
      ddos_threshold_rps: 5000,
      cache_policy: { mode: "aggressive", ttl_seconds: 300 },
      risk_thresholds: { allow: 50, challenge: 80, block: 95 },
    },
  },
};

const TIER_COLOR: Record<TierKey, string> = {
  critical: "#f5222d",
  high: "#fa8c16",
  medium: "#fadb14",
  catch_all: "#1677ff",
};

// waf_common::tier::HttpMethod variants (UPPERCASE serde).
const HTTP_METHODS = ["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"];

// Stable tooltip config — defined outside component to avoid new object on every render.
const SLIDER_TOOLTIP = { formatter: (v?: number) => `${v ?? 0}` };

const MONO_STYLE: React.CSSProperties = { fontFamily: "ui-monospace, monospace", fontSize: 12 };

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
    () => policy.risk_thresholds ?? DEFAULT_POLICY.risk_thresholds,
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
    const incoming = policy.risk_thresholds ?? DEFAULT_POLICY.risk_thresholds;
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

  // Cache mode switch: no_cache drops the TTL, the other modes require one —
  // keep the current TTL when present, else seed the mode's suggested value.
  const setCacheMode = useCallback((mode: CacheMode) => {
    const cur = policyRef.current.cache_policy;
    const next: CachePolicy =
      mode === "no_cache" ? { mode } : { mode, ttl_seconds: cur.ttl_seconds ?? DEFAULT_TTL[mode] };
    onChangeRef.current({ ...policyRef.current, cache_policy: next });
  }, []);

  const setCacheTtl = useCallback((ttl: number) => {
    const cur = policyRef.current.cache_policy;
    onChangeRef.current({ ...policyRef.current, cache_policy: { ...cur, ttl_seconds: ttl } });
  }, []);

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
  const cacheMode = policy.cache_policy?.mode ?? "no_cache";

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
          <Space.Compact style={{ width: "100%" }}>
            <Select
              value={cacheMode}
              onChange={setCacheMode}
              style={{ width: cacheMode === "no_cache" ? "100%" : "55%" }}
              options={[
                { value: "no_cache", label: t("tierPolicies.cacheNoCache") },
                { value: "short_ttl", label: t("tierPolicies.cacheShortTtl") },
                { value: "aggressive", label: t("tierPolicies.cacheAggressive") },
                { value: "default", label: t("tierPolicies.cacheDefault") },
              ]}
            />
            {cacheMode !== "no_cache" && (
              <Tooltip title={t("tierPolicies.cacheTtl")}>
                <InputNumber
                  min={1}
                  max={86400}
                  value={policy.cache_policy?.ttl_seconds ?? DEFAULT_TTL[cacheMode]}
                  onChange={(v) => v !== null && setCacheTtl(v)}
                  addonAfter="s"
                  style={{ width: "45%" }}
                />
              </Tooltip>
            )}
          </Space.Compact>
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

interface RuleFormValues {
  priority: number;
  tier: TierKey;
  path_kind: PathMatchKind;
  path_value?: string;
  method?: string[];
}

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
  const [form] = Form.useForm<RuleFormValues>();

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
          default_tier: (cfg as TierConfig).default_tier ?? "catch_all",
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
    // Depend on the stable fetch timestamp, not the `loadResult` object whose
    // identity changes every render. Because this effect rebuilds a NEW config
    // object on each run, depending on `loadResult` caused setConfig → re-render
    // → effect → setConfig … an infinite loop ("Maximum update depth exceeded")
    // that froze the router and blocked navigation away from this page.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loadQuery.dataUpdatedAt]);

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
          // Re-fetch from the server so the form reflects exactly what was
          // persisted (the load effect re-applies it on the new dataUpdatedAt).
          void loadQuery.refetch();
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

  const onDefaultTierChange = (tier: TierKey) => {
    isDirty.current = true;
    setConfig((prev) => ({ ...prev, default_tier: tier }));
  };

  // ── Classifier rules ─────────────────────────────────────────────────────────
  // The editor covers priority/tier/path/method. Rules may also carry `host`
  // and `headers` matchers (file-edited); those render read-only and are
  // preserved untouched on save because the full rule objects live in state.

  const onAddRule = async () => {
    const values = await form.validateFields();
    const newRule: ClassifierRule = {
      priority: values.priority,
      tier: values.tier,
      ...(values.path_value
        ? { path: { kind: values.path_kind, value: values.path_value } }
        : {}),
      ...(values.method?.length ? { method: values.method } : {}),
    };
    isDirty.current = true;
    setConfig((prev) => ({
      ...prev,
      classifier_rules: [...prev.classifier_rules, newRule],
    }));
    form.resetFields();
    setDrawerOpen(false);
  };

  const onDeleteRule = (index: number) => {
    isDirty.current = true;
    setConfig((prev) => ({
      ...prev,
      classifier_rules: prev.classifier_rules.filter((_, i) => i !== index),
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
      dataIndex: "host",
      ellipsis: true,
      render: (v?: HostMatch | null) =>
        v ? (
          <Tooltip title={t("tierPolicies.readOnlyMatcher")}>
            <span style={MONO_STYLE}>
              {v.kind}:{v.value}
            </span>
          </Tooltip>
        ) : (
          <span style={{ color: "#bfbfbf" }}>*</span>
        ),
    },
    {
      title: t("tierPolicies.pathMatch"),
      dataIndex: "path",
      ellipsis: true,
      render: (v?: PathMatch | null) =>
        v ? (
          <span style={MONO_STYLE}>
            {v.kind}:{v.value}
          </span>
        ) : (
          <span style={{ color: "#bfbfbf" }}>*</span>
        ),
    },
    {
      title: t("tierPolicies.methods"),
      dataIndex: "method",
      width: 180,
      render: (v?: string[] | null) =>
        v?.length
          ? v.map((m) => (
              <Tag key={m} style={{ fontSize: 11 }}>
                {m}
              </Tag>
            ))
          : <span style={{ color: "#bfbfbf" }}>{t("tierPolicies.allMethods")}</span>,
    },
    {
      title: t("tierPolicies.headers"),
      dataIndex: "headers",
      width: 140,
      ellipsis: true,
      render: (v?: HeaderMatch[] | null) =>
        v?.length ? (
          <Tooltip title={t("tierPolicies.readOnlyMatcher")}>
            <span style={MONO_STYLE}>
              {v.map((h) => h.name).join(", ")}
            </span>
          </Tooltip>
        ) : (
          <span style={{ color: "#bfbfbf" }}>*</span>
        ),
    },
    {
      title: "",
      key: "actions",
      width: 60,
      render: (_: unknown, __: ClassifierRule, index: number) => (
        <Popconfirm title={t("common.confirm")} onConfirm={() => onDeleteRule(index)}>
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
          <Space>
            <Tooltip title={t("tierPolicies.defaultTierHint")}>
              <span style={{ fontSize: 12, color: "#8c8c8c" }}>{t("tierPolicies.defaultTier")}</span>
            </Tooltip>
            <Select<TierKey>
              size="small"
              value={config.default_tier}
              onChange={onDefaultTierChange}
              style={{ width: 120 }}
              options={TIER_KEYS.map((k) => ({ value: k, label: TIER_LABELS[k] }))}
            />
            <Button
              size="small"
              type="primary"
              icon={<PlusOutlined />}
              onClick={() => setDrawerOpen(true)}
            >
              {t("tierPolicies.addRule")}
            </Button>
          </Space>
        }
      >
        <Table<ClassifierRule>
          rowKey={(_, index) => index ?? 0}
          size="small"
          dataSource={config.classifier_rules}
          columns={ruleColumns}
          pagination={false}
          locale={{ emptyText: t("tierPolicies.noRules") }}
          scroll={{ x: 800 }}
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
                <Space wrap>
                  <span>{t("tierPolicies.matchedTier")}:</span>
                  <Tag color={TIER_COLOR[testResult.matched_tier as TierKey] ?? "default"}>
                    {testResult.matched_tier}
                  </Tag>
                  {testResult.policy && (
                    <span style={{ color: "#8c8c8c", fontSize: 12 }}>
                      {t("tierPolicies.failMode")}: {testResult.policy.fail_mode} ·{" "}
                      {testResult.policy.ddos_threshold_rps} rps ·{" "}
                      {testResult.policy.risk_thresholds.allow}/
                      {testResult.policy.risk_thresholds.challenge}/
                      {testResult.policy.risk_thresholds.block}
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
        <Form
          form={form}
          layout="vertical"
          initialValues={{ priority: 100, tier: "medium", path_kind: "prefix" }}
        >
          <Form.Item name="priority" label={t("tierPolicies.priority")} rules={[{ required: true }]}>
            <InputNumber min={1} max={9999} style={{ width: "100%" }} />
          </Form.Item>
          <Form.Item name="tier" label={t("tierPolicies.tier")} rules={[{ required: true }]}>
            <Select
              options={TIER_KEYS.map((k) => ({ value: k, label: TIER_LABELS[k] }))}
            />
          </Form.Item>
          <Form.Item label={t("tierPolicies.pathMatch")}>
            <Space.Compact style={{ width: "100%" }}>
              <Form.Item name="path_kind" noStyle>
                <Select
                  style={{ width: "35%" }}
                  options={[
                    { value: "prefix", label: t("tierPolicies.kindPrefix") },
                    { value: "exact", label: t("tierPolicies.kindExact") },
                    { value: "regex", label: t("tierPolicies.kindRegex") },
                  ]}
                />
              </Form.Item>
              <Form.Item name="path_value" noStyle>
                <Input placeholder="/api/payments" style={{ ...MONO_STYLE, width: "65%" }} />
              </Form.Item>
            </Space.Compact>
          </Form.Item>
          <Form.Item name="method" label={t("tierPolicies.methods")}>
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
