import {
  Card,
  Row,
  Col,
  Typography,
  Space,
  Button,
  Input,
  Select,
  Switch,
  Tabs,
  Tag,
  Alert,
  Badge,
  Segmented,
  Popconfirm,
  App,
} from "antd";
import {
  SaveOutlined,
  ReloadOutlined,
  ExperimentOutlined,
  SafetyOutlined,
  StopOutlined,
} from "@ant-design/icons";
import { useCustom, useCustomMutation } from "@refinedev/core";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

// ── Types ──────────────────────────────────────────────────────────────────────

interface AccessConfig {
  version: number;
  dry_run: boolean;
  ip_whitelist: string[];
  ip_blacklist: string[];
  host_whitelist: {
    critical: string[];
    high: string[];
    medium: string[];
    catch_all: string[];
  };
  tier_whitelist_mode: {
    critical: string;
    high: string;
    medium: string;
    catch_all: string;
  };
}

type Tier = "critical" | "high" | "medium" | "catch_all";

interface TestResult {
  verdict: "allow" | "block" | "bypass" | string;
  reason?: string;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function parseLines(raw: string): string[] {
  return raw
    .split(/[\n\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function joinLines(arr: string[]): string {
  return arr.join("\n");
}

function verdictColor(v: string): "green" | "red" | "blue" | "default" {
  if (v === "allow" || v === "bypass") return "green";
  if (v === "block") return "red";
  return "default";
}

const TIERS: { key: Tier; label: string }[] = [
  { key: "critical", label: "Critical" },
  { key: "high", label: "High" },
  { key: "medium", label: "Medium" },
  { key: "catch_all", label: "Catch-All" },
];

const WHITELIST_MODES = [
  { value: "full_bypass", label: "Full Bypass" },
  { value: "blacklist_only", label: "Blacklist Only" },
];

// ── Sub-component: IP list editor ─────────────────────────────────────────────

interface IpListCardProps {
  title: string;
  value: string[];
  onChange: (next: string[]) => void;
  color?: "green" | "red";
}

const IpListCard: React.FC<IpListCardProps> = ({ title, value, onChange, color = "green" }) => {
  const [raw, setRaw] = useState(joinLines(value));
  const { t } = useTranslation();

  useEffect(() => {
    setRaw(joinLines(value));
  }, [value]);

  const onBlur = () => {
    onChange(parseLines(raw));
  };

  const count = parseLines(raw).length;
  const warn = count > 50_000;

  return (
    <Card
      size="small"
      title={
        <Space>
          {color === "green" ? (
            <SafetyOutlined style={{ color: "#52c41a" }} />
          ) : (
            <StopOutlined style={{ color: "#f5222d" }} />
          )}
          <span>{title}</span>
          <Badge
            count={count}
            overflowCount={999_999}
            style={{ backgroundColor: color === "green" ? "#52c41a" : "#f5222d" }}
          />
        </Space>
      }
    >
      {warn && (
        <Alert
          type="warning"
          showIcon
          message={t("accessLists.largeListWarning")}
          style={{ marginBottom: 8 }}
        />
      )}
      <Input.TextArea
        value={raw}
        onChange={(e) => setRaw(e.target.value)}
        onBlur={onBlur}
        rows={8}
        placeholder="1.2.3.4&#10;10.0.0.0/8"
        style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}
      />
      <Typography.Text type="secondary" style={{ fontSize: 11 }}>
        {t("accessLists.parseHint")}
      </Typography.Text>
    </Card>
  );
};

// ── Sub-component: Host whitelist tier ────────────────────────────────────────

interface TierHostCardProps {
  tier: Tier;
  hosts: string[];
  mode: string;
  onHostsChange: (tier: Tier, hosts: string[]) => void;
  onModeChange: (tier: Tier, mode: string) => void;
}

const TierHostCard: React.FC<TierHostCardProps> = ({
  tier,
  hosts,
  mode,
  onHostsChange,
  onModeChange,
}) => {
  const [input, setInput] = useState("");
  const [localHosts, setLocalHosts] = useState<string[]>(hosts);
  const { t } = useTranslation();

  useEffect(() => {
    setLocalHosts(hosts);
  }, [hosts]);

  const addHost = () => {
    const v = input.trim();
    if (v && !localHosts.includes(v)) {
      const next = [...localHosts, v];
      setLocalHosts(next);
      onHostsChange(tier, next);
    }
    setInput("");
  };

  const removeHost = (h: string) => {
    const next = localHosts.filter((x) => x !== h);
    setLocalHosts(next);
    onHostsChange(tier, next);
  };

  const isCriticalFullBypass = tier === "critical" && mode === "full_bypass";

  return (
    <Space direction="vertical" style={{ width: "100%" }} size="small">
      <Space align="center">
        <Typography.Text strong>{t("accessLists.tierMode")}</Typography.Text>
        {isCriticalFullBypass ? (
          <Popconfirm
            title={t("accessLists.criticalBypassWarning")}
            description={t("accessLists.criticalBypassDesc")}
            onConfirm={() => onModeChange(tier, "full_bypass")}
            okType="danger"
          >
            <Segmented
              value={mode}
              options={WHITELIST_MODES}
            />
          </Popconfirm>
        ) : (
          <Segmented
            value={mode}
            options={WHITELIST_MODES}
            onChange={(v) => onModeChange(tier, String(v))}
          />
        )}
      </Space>
      <Space.Compact style={{ width: "100%" }}>
        <Input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="example.com"
          onPressEnter={addHost}
        />
        <Button onClick={addHost}>{t("common.add")}</Button>
      </Space.Compact>
      <Space wrap size={[4, 4]}>
        {localHosts.length === 0 ? (
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {t("accessLists.noHosts")}
          </Typography.Text>
        ) : (
          localHosts.map((h) => (
            <Tag
              key={h}
              closable
              onClose={() => removeHost(h)}
              style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}
            >
              {h}
            </Tag>
          ))
        )}
      </Space>
    </Space>
  );
};

// ── Page ──────────────────────────────────────────────────────────────────────

export const AccessListsPage: React.FC = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();

  const [config, setConfig] = useState<AccessConfig>({
    version: 1,
    dry_run: false,
    ip_whitelist: [],
    ip_blacklist: [],
    host_whitelist: { critical: [], high: [], medium: [], catch_all: [] },
    tier_whitelist_mode: {
      critical: "blacklist_only",
      high: "blacklist_only",
      medium: "blacklist_only",
      catch_all: "blacklist_only",
    },
  });

  // ── Tester state ──────────────────────────────────────────────────────────

  const [testIp, setTestIp] = useState("");
  const [testHost, setTestHost] = useState("");
  const [testTier, setTestTier] = useState<Tier>("critical");
  const [testResult, setTestResult] = useState<TestResult | null>(null);

  // ── API: load config ──────────────────────────────────────────────────────

  const configQuery = useCustom<AccessConfig>({
    url: "/api/access-lists",
    method: "get",
    queryOptions: { staleTime: 30_000, retry: false },
    errorNotification: false,
  });

  const remoteData = configQuery.result?.data;

  useEffect(() => {
    if (!remoteData || typeof remoteData !== "object") return;
    const c = remoteData as Partial<AccessConfig>;
    setConfig({
      version: c.version ?? 1,
      dry_run: c.dry_run ?? false,
      ip_whitelist: Array.isArray(c.ip_whitelist) ? c.ip_whitelist : [],
      ip_blacklist: Array.isArray(c.ip_blacklist) ? c.ip_blacklist : [],
      host_whitelist: {
        critical: c.host_whitelist?.critical ?? [],
        high: c.host_whitelist?.high ?? [],
        medium: c.host_whitelist?.medium ?? [],
        catch_all: c.host_whitelist?.catch_all ?? [],
      },
      tier_whitelist_mode: {
        critical: c.tier_whitelist_mode?.critical ?? "blacklist_only",
        high: c.tier_whitelist_mode?.high ?? "blacklist_only",
        medium: c.tier_whitelist_mode?.medium ?? "blacklist_only",
        catch_all: c.tier_whitelist_mode?.catch_all ?? "blacklist_only",
      },
    });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [remoteData]);

  // ── API: save ─────────────────────────────────────────────────────────────

  const { mutate: saveConfig, mutation: saveMutation } = useCustomMutation();
  const saving = saveMutation.isPending;

  const onSave = () => {
    saveConfig(
      { url: "/api/access-lists", method: "put", values: config },
      {
        onSuccess: () => {
          message.success(t("accessLists.saved"));
          configQuery.query.refetch();
        },
        onError: (err) => message.error(err.message),
      },
    );
  };

  // ── API: test ─────────────────────────────────────────────────────────────

  const testQuery = useCustom<TestResult>({
    url: "/api/access-lists/test",
    method: "get",
    config: { query: { ip: testIp, host: testHost, tier: testTier } },
    queryOptions: { enabled: false, retry: false },
    errorNotification: false,
  });

  const onTest = () => {
    setTestResult(null);
    testQuery.query.refetch();
  };

  const testData = testQuery.result?.data;

  useEffect(() => {
    const d = testData as TestResult | undefined;
    if (d && typeof d.verdict === "string") setTestResult(d);
  }, [testData]);

  // ── Config mutators ───────────────────────────────────────────────────────

  const setIpWhitelist = (ips: string[]) =>
    setConfig((c) => ({ ...c, ip_whitelist: ips }));

  const setIpBlacklist = (ips: string[]) =>
    setConfig((c) => ({ ...c, ip_blacklist: ips }));

  const setTierHosts = (tier: Tier, hosts: string[]) =>
    setConfig((c) => ({
      ...c,
      host_whitelist: { ...c.host_whitelist, [tier]: hosts },
    }));

  const setTierMode = (tier: Tier, mode: string) =>
    setConfig((c) => ({
      ...c,
      tier_whitelist_mode: { ...c.tier_whitelist_mode, [tier]: mode },
    }));

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      {/* Header */}
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <div>
          <Typography.Title level={4} style={{ margin: 0 }}>
            {t("accessLists.title")}
          </Typography.Title>
          <Space size="small" style={{ marginTop: 4 }}>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {t("accessLists.version")}: v{config.version}
            </Typography.Text>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>·</Typography.Text>
            <Space size={4}>
              <Switch
                size="small"
                checked={config.dry_run}
                onChange={(v) => setConfig((c) => ({ ...c, dry_run: v }))}
              />
              <Typography.Text style={{ fontSize: 12 }}>
                {t("accessLists.dryRun")}
              </Typography.Text>
              {config.dry_run && (
                <Tag color="orange" style={{ fontSize: 11 }}>
                  {t("accessLists.dryRunActive")}
                </Tag>
              )}
            </Space>
          </Space>
        </div>
        <Space>
          <Button
            icon={<ReloadOutlined spin={configQuery.query.isFetching} />}
            onClick={() => configQuery.query.refetch()}
          >
            {t("common.refresh")}
          </Button>
          <Button type="primary" icon={<SaveOutlined />} loading={saving} onClick={onSave}>
            {t("common.save")}
          </Button>
        </Space>
      </Space>

      {configQuery.query.isError && (
        <Alert
          type="warning"
          showIcon
          message={t("accessLists.configUnavailable")}
          description="GET /api/access-lists endpoint is not available."
        />
      )}

      {/* IP lists */}
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={12}>
          <IpListCard
            title={t("accessLists.ipWhitelist")}
            value={config.ip_whitelist}
            onChange={setIpWhitelist}
            color="green"
          />
        </Col>
        <Col xs={24} lg={12}>
          <IpListCard
            title={t("accessLists.ipBlacklist")}
            value={config.ip_blacklist}
            onChange={setIpBlacklist}
            color="red"
          />
        </Col>
      </Row>

      {/* Per-tier host whitelist */}
      <Card size="small" title={t("accessLists.tierHostWhitelist")}>
        <Tabs
          items={TIERS.map(({ key, label }) => ({
            key,
            label: (
              <Space size={4}>
                <span>{label}</span>
                <Badge
                  count={config.host_whitelist?.[key]?.length ?? 0}
                  style={{ backgroundColor: "#1677ff" }}
                  overflowCount={9999}
                />
              </Space>
            ),
            children: (
              <TierHostCard
                tier={key}
                hosts={config.host_whitelist?.[key] ?? []}
                mode={config.tier_whitelist_mode?.[key] ?? "blacklist_only"}
                onHostsChange={setTierHosts}
                onModeChange={setTierMode}
              />
            ),
          }))}
        />
      </Card>

      {/* Decision tester (sticky-ish at bottom) */}
      <Card
        size="small"
        title={
          <Space>
            <ExperimentOutlined />
            <span>{t("accessLists.decisionTester")}</span>
          </Space>
        }
        style={{ position: "sticky", bottom: 16 }}
      >
        {testQuery.query.isError && (
          <Alert
            type="warning"
            showIcon
            message="GET /api/access-lists/test endpoint is not available."
            style={{ marginBottom: 12 }}
          />
        )}
        <Row gutter={[12, 12]} align="middle">
          <Col xs={24} sm={8}>
            <Input
              prefix={<Typography.Text type="secondary" style={{ fontSize: 11 }}>IP</Typography.Text>}
              value={testIp}
              onChange={(e) => setTestIp(e.target.value)}
              placeholder="1.2.3.4"
              onPressEnter={onTest}
            />
          </Col>
          <Col xs={24} sm={7}>
            <Input
              prefix={<Typography.Text type="secondary" style={{ fontSize: 11 }}>Host</Typography.Text>}
              value={testHost}
              onChange={(e) => setTestHost(e.target.value)}
              placeholder="example.com"
              onPressEnter={onTest}
            />
          </Col>
          <Col xs={12} sm={5}>
            <Select
              style={{ width: "100%" }}
              value={testTier}
              onChange={setTestTier}
              options={TIERS.map(({ key, label }) => ({ value: key, label }))}
            />
          </Col>
          <Col xs={12} sm={4}>
            <Button
              type="primary"
              style={{ width: "100%" }}
              loading={testQuery.query.isFetching}
              onClick={onTest}
            >
              {t("common.test")}
            </Button>
          </Col>
        </Row>
        {testResult && (
          <div style={{ marginTop: 12 }}>
            <Space>
              <Tag
                color={verdictColor(testResult.verdict ?? "")}
                style={{ fontSize: 14, padding: "2px 12px" }}
              >
                {(testResult.verdict ?? "unknown").toUpperCase()}
              </Tag>
              {testResult.reason && (
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  {testResult.reason}
                </Typography.Text>
              )}
            </Space>
          </div>
        )}
      </Card>
    </Space>
  );
};
