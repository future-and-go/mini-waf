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
  InputNumber,
  Select,
  Form,
  Input,
  Drawer,
  Modal,
  Alert,
  Collapse,
  Divider,
  App,
} from "antd";
import {
  ReloadOutlined,
  UserOutlined,
  RiseOutlined,
  DashboardOutlined,
  ThunderboltOutlined,
} from "@ant-design/icons";
import { useCustom, useCustomMutation } from "@refinedev/core";
import { Column } from "@ant-design/plots";
import type { ColumnsType } from "antd/es/table";
import { useTranslation } from "react-i18next";
import { useEffect, useMemo, useState } from "react";
import { KpiCard } from "../../components/kpi-card";
import { fmtDateTime, fmtAge } from "../../utils/format";

// ── Types ──────────────────────────────────────────────────────────────────────

interface RiskConfig {
  enabled: boolean;
  ttl_secs: number;
  gc_interval_secs: number;
  decay: { min_clean_streak: number; decay_rate: number; max_decay: number };
  canary: { enabled: boolean; paths: string[]; ban_ttl_secs: number };
  store: { backend: "memory" | "redis"; redis?: { url: string; prefix?: string } };
}

interface RiskActor {
  id: string;
  key: { ip?: string; fp?: string; session?: string };
  score: number;
  contributors_count: number;
  last_seen_ms: number;
}

interface RiskMetrics {
  actor_count: number;
  avg_score: number;
  p95_score: number;
  scored_last_hour: number;
  blocked_last_hour: number;
  challenged_last_hour: number;
}

interface ActorsResponse {
  data?: RiskActor[];
  total?: number;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function scoreColor(score: number): string {
  if (score >= 80) return "red";
  if (score >= 50) return "orange";
  if (score >= 20) return "gold";
  return "green";
}

function formatKey(key: RiskActor["key"]): string {
  return key?.ip ?? key?.fp ?? key?.session ?? "—";
}

function truncateKey(key: RiskActor["key"], max = 24): string {
  const full = formatKey(key);
  return full.length > max ? `${full.slice(0, max)}…` : full;
}

function buildDistributionData(actors: RiskActor[]) {
  const bins = Array.from({ length: 10 }, (_, i) => ({
    range: `${i * 10}-${(i + 1) * 10}`,
    count: 0,
  }));
  for (const a of actors) {
    const idx = Math.min(Math.floor(a.score / 10), 9);
    bins[idx].count += 1;
  }
  return bins;
}

// ── Page ──────────────────────────────────────────────────────────────────────

export const RiskScoringPage: React.FC = () => {
  const { t } = useTranslation();
  const { message, modal } = App.useApp();
  const [configForm] = Form.useForm<RiskConfig>();
  const [canaryInput, setCanaryInput] = useState("");
  const [canaryPaths, setCanaryPaths] = useState<string[]>([]);
  const [page, setPage] = useState(1);
  const [drawerActor, setDrawerActor] = useState<RiskActor | null>(null);
  const [creditModalOpen, setCreditModalOpen] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const interval = autoRefresh ? 30_000 : (false as const);

  // ── API: metrics ──────────────────────────────────────────────────────────

  const metricsQuery = useCustom<RiskMetrics>({
    url: "/api/risk/metrics",
    method: "get",
    queryOptions: { staleTime: 0, refetchInterval: interval },
  });
  const metrics = metricsQuery.result?.data;
  const metricsError = metricsQuery.query.isError;

  // ── API: config ───────────────────────────────────────────────────────────

  const configQuery = useCustom<RiskConfig>({
    url: "/api/risk/config",
    method: "get",
    queryOptions: { staleTime: 60_000 },
  });

  useEffect(() => {
    const c = configQuery.result?.data;
    if (!c) return;
    configForm.setFieldsValue(c);
    setCanaryPaths(c.canary?.paths ?? []);
  }, [configQuery.result, configForm]);

  // ── API: actors (paginated) ───────────────────────────────────────────────

  const actorsQuery = useCustom<ActorsResponse>({
    url: "/api/risk/actors",
    method: "get",
    config: { query: { limit: 50, min_score: 0, page } },
    queryOptions: { staleTime: 0, refetchInterval: interval },
  });
  const actors: RiskActor[] = Array.isArray(actorsQuery.result?.data?.data)
    ? (actorsQuery.result.data.data as RiskActor[])
    : Array.isArray(actorsQuery.result?.data)
      ? (actorsQuery.result.data as unknown as RiskActor[])
      : [];
  const actorsTotal = actorsQuery.result?.data?.total ?? actors.length;

  const distributionData = useMemo(() => buildDistributionData(actors), [actors]);

  // ── API: mutations ────────────────────────────────────────────────────────

  const { mutate: saveConfig, mutation: saveMutation } = useCustomMutation();
  const { mutate: creditActor, mutation: creditMutation } = useCustomMutation();
  const { mutate: clearActor } = useCustomMutation();
  const saving = saveMutation.isPending;

  const onSaveConfig = async () => {
    const v = await configForm.validateFields();
    const payload = { ...v, canary: { ...v.canary, paths: canaryPaths } };
    saveConfig(
      { url: "/api/risk/config", method: "put", values: payload },
      {
        onSuccess: () => message.success(t("risk.configSaved")),
        onError: (err) => message.error(err.message),
      },
    );
  };

  const onCredit = (amount: number) => {
    if (!drawerActor) return;
    creditActor(
      { url: `/api/risk/actors/${drawerActor.id}/credit`, method: "post", values: { amount } },
      {
        onSuccess: () => {
          message.success(t("risk.creditApplied"));
          setCreditModalOpen(false);
          actorsQuery.query.refetch();
        },
        onError: (err) => message.error(err.message),
      },
    );
  };

  const onClearScore = () => {
    if (!drawerActor) return;
    modal.confirm({
      title: t("risk.clearConfirmTitle"),
      content: t("risk.clearConfirmContent"),
      onOk: () =>
        clearActor(
          { url: `/api/risk/actors/${drawerActor.id}/clear`, method: "post", values: {} },
          {
            onSuccess: () => {
              message.success(t("risk.scoreCleared"));
              setDrawerActor(null);
              actorsQuery.query.refetch();
            },
            onError: (err) => message.error(err.message),
          },
        ),
    });
  };

  const storeBackend = Form.useWatch(["store", "backend"], configForm);

  // ── Canary path tag helpers ───────────────────────────────────────────────

  const addCanaryPath = () => {
    const v = canaryInput.trim();
    if (v && !canaryPaths.includes(v)) setCanaryPaths((p) => [...p, v]);
    setCanaryInput("");
  };

  const removeCanaryPath = (path: string) =>
    setCanaryPaths((p) => p.filter((x) => x !== path));

  // ── Table columns ─────────────────────────────────────────────────────────

  const columns: ColumnsType<RiskActor> = [
    {
      title: t("risk.actorKey"),
      key: "key",
      render: (_: unknown, r: RiskActor) => (
        <Typography.Text
          style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}
          title={formatKey(r.key)}
        >
          {truncateKey(r.key)}
        </Typography.Text>
      ),
    },
    {
      title: t("risk.score"),
      dataIndex: "score",
      width: 100,
      sorter: (a: RiskActor, b: RiskActor) => a.score - b.score,
      render: (v: number) => <Tag color={scoreColor(v)}>{v}</Tag>,
    },
    {
      title: t("risk.contributors"),
      dataIndex: "contributors_count",
      width: 120,
      render: (v: number) => v,
    },
    {
      title: t("risk.lastSeen"),
      dataIndex: "last_seen_ms",
      width: 140,
      render: (v: number) => (
        <span style={{ color: "#8c8c8c", fontSize: 12 }}>{fmtAge(v)}</span>
      ),
    },
    {
      title: t("common.actions"),
      key: "actions",
      width: 100,
      render: (_: unknown, r: RiskActor) => (
        <Button size="small" type="link" onClick={() => setDrawerActor(r)}>
          {t("common.details")}
        </Button>
      ),
    },
  ];

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      {/* Header */}
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <div>
          <Typography.Title level={4} style={{ margin: 0 }}>
            {t("risk.title")}
          </Typography.Title>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {t("risk.subtitle")}
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
            icon={<ReloadOutlined spin={metricsQuery.query.isFetching} />}
            onClick={() => {
              metricsQuery.query.refetch();
              actorsQuery.query.refetch();
            }}
          >
            {t("common.refresh")}
          </Button>
        </Space>
      </Space>

      {/* Metrics error fallback */}
      {metricsError && (
        <Alert
          type="warning"
          showIcon
          message={t("risk.metricsUnavailable")}
          description="GET /api/risk/metrics endpoint is not available."
        />
      )}

      {/* KPI row */}
      <Row gutter={[16, 16]}>
        <Col xs={12} sm={8} lg={4}>
          <KpiCard
            label={t("risk.actorCount")}
            value={metrics?.actor_count ?? "—"}
            icon={UserOutlined}
            color="blue"
            loading={metricsQuery.query.isLoading}
          />
        </Col>
        <Col xs={12} sm={8} lg={4}>
          <KpiCard
            label={t("risk.avgScore")}
            value={metrics?.avg_score != null ? metrics.avg_score.toFixed(1) : "—"}
            icon={DashboardOutlined}
            color="teal"
            loading={metricsQuery.query.isLoading}
          />
        </Col>
        <Col xs={12} sm={8} lg={4}>
          <KpiCard
            label={t("risk.p95Score")}
            value={metrics?.p95_score != null ? metrics.p95_score.toFixed(1) : "—"}
            icon={RiseOutlined}
            color="orange"
            loading={metricsQuery.query.isLoading}
          />
        </Col>
        <Col xs={12} sm={8} lg={4}>
          <KpiCard
            label={t("risk.scoredLastHour")}
            value={metrics?.scored_last_hour ?? "—"}
            icon={ThunderboltOutlined}
            color="purple"
            loading={metricsQuery.query.isLoading}
          />
        </Col>
        <Col xs={12} sm={8} lg={4}>
          <KpiCard
            label={t("risk.blockedLastHour")}
            value={metrics?.blocked_last_hour ?? "—"}
            icon={ThunderboltOutlined}
            color="red"
            loading={metricsQuery.query.isLoading}
          />
        </Col>
        <Col xs={12} sm={8} lg={4}>
          <KpiCard
            label={t("risk.challengedLastHour")}
            value={metrics?.challenged_last_hour ?? "—"}
            icon={ThunderboltOutlined}
            color="indigo"
            loading={metricsQuery.query.isLoading}
          />
        </Col>
      </Row>

      {/* Config card */}
      <Card
        title={t("risk.configuration")}
        loading={configQuery.query.isLoading}
        extra={
          <Button type="primary" loading={saving} onClick={onSaveConfig}>
            {t("common.save")}
          </Button>
        }
      >
        {configQuery.query.isError ? (
          <Alert
            type="warning"
            showIcon
            message={t("risk.configUnavailable")}
            description="GET /api/risk/config endpoint is not available."
          />
        ) : (
          <Form form={configForm} layout="vertical">
            <Collapse
              ghost
              defaultActiveKey={["general"]}
              items={[
                {
                  key: "general",
                  label: t("risk.general"),
                  children: (
                    <Row gutter={16}>
                      <Col xs={24} sm={6}>
                        <Form.Item
                          name="enabled"
                          valuePropName="checked"
                          label={t("risk.enabled")}
                        >
                          <Switch />
                        </Form.Item>
                      </Col>
                      <Col xs={24} sm={9}>
                        <Form.Item name="ttl_secs" label={t("risk.ttlSecs")}>
                          <InputNumber min={1} style={{ width: "100%" }} />
                        </Form.Item>
                      </Col>
                      <Col xs={24} sm={9}>
                        <Form.Item
                          name="gc_interval_secs"
                          label={t("risk.gcIntervalSecs")}
                        >
                          <InputNumber min={1} style={{ width: "100%" }} />
                        </Form.Item>
                      </Col>
                    </Row>
                  ),
                },
                {
                  key: "store",
                  label: t("risk.store"),
                  children: (
                    <>
                      <Form.Item
                        name={["store", "backend"]}
                        label={t("risk.storeBackend")}
                      >
                        <Select
                          style={{ width: 200 }}
                          options={[
                            { value: "memory", label: "Memory" },
                            { value: "redis", label: "Redis" },
                          ]}
                        />
                      </Form.Item>
                      {storeBackend === "redis" && (
                        <Row gutter={16}>
                          <Col xs={24} sm={16}>
                            <Form.Item
                              name={["store", "redis", "url"]}
                              label={t("risk.redisUrl")}
                              rules={[{ required: true }]}
                            >
                              <Input placeholder="redis://127.0.0.1:6379" />
                            </Form.Item>
                          </Col>
                          <Col xs={24} sm={8}>
                            <Form.Item
                              name={["store", "redis", "prefix"]}
                              label={t("risk.redisPrefix")}
                            >
                              <Input placeholder="risk:" />
                            </Form.Item>
                          </Col>
                        </Row>
                      )}
                    </>
                  ),
                },
                {
                  key: "decay",
                  label: t("risk.decay"),
                  children: (
                    <Row gutter={16}>
                      <Col xs={24} sm={8}>
                        <Form.Item
                          name={["decay", "min_clean_streak"]}
                          label={t("risk.minCleanStreak")}
                        >
                          <InputNumber min={0} style={{ width: "100%" }} />
                        </Form.Item>
                      </Col>
                      <Col xs={24} sm={8}>
                        <Form.Item
                          name={["decay", "decay_rate"]}
                          label={t("risk.decayRate")}
                        >
                          <InputNumber min={0} max={50} style={{ width: "100%" }} />
                        </Form.Item>
                      </Col>
                      <Col xs={24} sm={8}>
                        <Form.Item
                          name={["decay", "max_decay"]}
                          label={t("risk.maxDecay")}
                        >
                          <InputNumber min={0} style={{ width: "100%" }} />
                        </Form.Item>
                      </Col>
                    </Row>
                  ),
                },
                {
                  key: "canary",
                  label: t("risk.canary"),
                  children: (
                    <>
                      <Row gutter={16} style={{ marginBottom: 12 }}>
                        <Col xs={24} sm={8}>
                          <Form.Item
                            name={["canary", "enabled"]}
                            valuePropName="checked"
                            label={t("risk.canaryEnabled")}
                          >
                            <Switch />
                          </Form.Item>
                        </Col>
                        <Col xs={24} sm={16}>
                          <Form.Item
                            name={["canary", "ban_ttl_secs"]}
                            label={t("risk.canaryBanTtl")}
                          >
                            <InputNumber min={1} style={{ width: "100%" }} />
                          </Form.Item>
                        </Col>
                      </Row>
                      <Form.Item label={t("risk.canaryPaths")}>
                        <Space.Compact style={{ width: "100%", marginBottom: 8 }}>
                          <Input
                            value={canaryInput}
                            onChange={(e) => setCanaryInput(e.target.value)}
                            placeholder="/canary/trap"
                            onPressEnter={addCanaryPath}
                          />
                          <Button onClick={addCanaryPath}>{t("common.add")}</Button>
                        </Space.Compact>
                        <Space wrap>
                          {canaryPaths.map((p) => (
                            <Tag
                              key={p}
                              closable
                              onClose={() => removeCanaryPath(p)}
                              style={{ fontFamily: "ui-monospace, monospace" }}
                            >
                              {p}
                            </Tag>
                          ))}
                        </Space>
                      </Form.Item>
                    </>
                  ),
                },
              ]}
            />
          </Form>
        )}
      </Card>

      {/* Distribution chart + Actors table */}
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={10}>
          <Card title={t("risk.distribution")} size="small">
            {actors.length > 0 ? (
              <Column
                data={distributionData}
                xField="range"
                yField="count"
                height={220}
                animate={false}
                label={{ position: "top" }}
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
                <Typography.Text type="secondary">{t("risk.noActors")}</Typography.Text>
              </div>
            )}
          </Card>
        </Col>

        <Col xs={24} lg={14}>
          <Card size="small" title={t("risk.liveActors")}>
            {actorsQuery.query.isError ? (
              <Alert
                type="warning"
                showIcon
                message={t("risk.actorsUnavailable")}
                description="GET /api/risk/actors endpoint is not available."
              />
            ) : (
              <Table<RiskActor>
                rowKey="id"
                size="small"
                dataSource={actors}
                columns={columns}
                loading={actorsQuery.query.isLoading}
                onRow={(r) => ({ onClick: () => setDrawerActor(r) })}
                pagination={{
                  current: page,
                  pageSize: 50,
                  total: actorsTotal,
                  onChange: (p) => setPage(p),
                  showTotal: (n) => `${t("common.total")}: ${n}`,
                }}
                scroll={{ x: 600 }}
              />
            )}
          </Card>
        </Col>
      </Row>

      {/* Actor detail drawer */}
      <Drawer
        title={t("risk.actorDetail")}
        open={!!drawerActor}
        onClose={() => setDrawerActor(null)}
        width={480}
        extra={
          <Space>
            <Button
              onClick={() => setCreditModalOpen(true)}
              disabled={!drawerActor}
            >
              {t("risk.addCredit")}
            </Button>
            <Button danger onClick={onClearScore} disabled={!drawerActor}>
              {t("risk.clearScore")}
            </Button>
          </Space>
        }
      >
        {drawerActor && (
          <Space direction="vertical" style={{ width: "100%" }}>
            <Typography.Text strong>{t("risk.actorKey")}</Typography.Text>
            <Typography.Text
              copyable
              code
              style={{ fontSize: 12 }}
            >
              {formatKey(drawerActor.key)}
            </Typography.Text>
            <Divider />
            <Row gutter={16}>
              <Col span={12}>
                <Typography.Text type="secondary">{t("risk.score")}</Typography.Text>
                <div>
                  <Tag color={scoreColor(drawerActor.score)} style={{ fontSize: 16 }}>
                    {drawerActor.score}
                  </Tag>
                </div>
              </Col>
              <Col span={12}>
                <Typography.Text type="secondary">{t("risk.contributors")}</Typography.Text>
                <div>
                  <Typography.Text strong>{drawerActor.contributors_count}</Typography.Text>
                </div>
              </Col>
            </Row>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {t("risk.lastSeen")}: {fmtDateTime(drawerActor.last_seen_ms)}
            </Typography.Text>
          </Space>
        )}
      </Drawer>

      {/* Credit modal */}
      <Modal
        title={t("risk.addCreditTitle")}
        open={creditModalOpen}
        onCancel={() => setCreditModalOpen(false)}
        footer={null}
        destroyOnClose
      >
        <Space direction="vertical" style={{ width: "100%" }}>
          <Typography.Text type="secondary">{t("risk.creditHint")}</Typography.Text>
          <Space>
            {([-50, -25, -10] as const).map((amt) => (
              <Button
                key={amt}
                onClick={() => onCredit(amt)}
                loading={creditMutation.isPending}
              >
                {amt}
              </Button>
            ))}
          </Space>
        </Space>
      </Modal>
    </Space>
  );
};
