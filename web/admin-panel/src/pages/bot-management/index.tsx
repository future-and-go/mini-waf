import {
  Card,
  Button,
  Space,
  Table,
  Tag,
  Modal,
  Form,
  Input,
  Select,
  Tabs,
  Alert,
  Typography,
  App,
} from "antd";
import { useCustom, useCustomMutation } from "@refinedev/core";
import type { ColumnsType } from "antd/es/table";
import { useTranslation } from "react-i18next";
import { useMemo, useState } from "react";
import type { BotPattern, SecurityEvent, StatsOverview } from "../../types/api";
import { TopList } from "../../components/top-list";
import { fmtDateTime } from "../../utils/format";

interface PatternsResponse {
  patterns?: BotPattern[];
}

interface PatternForm {
  pattern: string;
  name: string;
  action: string;
  description: string;
}

interface TestMatch {
  id: string;
  name: string;
  action: string;
}

const TABS = [
  { key: "good", i18nKey: "botManagement.goodBots", tag: "good-bot" },
  { key: "bad", i18nKey: "botManagement.badBots", tag: "scraper" },
  { key: "ai", i18nKey: "botManagement.aiCrawlers", tag: "ai-crawler" },
  { key: "seo", i18nKey: "botManagement.seoTools", tag: "seo-tool" },
  { key: "custom", i18nKey: "botManagement.custom", tag: "custom" },
  { key: "relay-proxy", i18nKey: "botManagement.relayProxy", tag: "relay-proxy" },
] as const;

export const BotManagementPage: React.FC = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [form] = Form.useForm<PatternForm>();
  const [open, setOpen] = useState(false);
  const [tab, setTab] = useState<string>("bad");
  const [testUa, setTestUa] = useState("");
  const [testResult, setTestResult] = useState<TestMatch[] | null>(null);

  const { result, query } = useCustom<PatternsResponse>({
    url: "/api/bot-patterns",
    method: "get",
    queryOptions: { staleTime: 60_000 },
  });

  const relayQuery = useCustom<{ data: SecurityEvent[]; total: number }>({
    url: "/api/security-events",
    method: "get",
    config: { query: { rule_id: "BOT-RELAY", page_size: 50, page: 1 } },
    queryOptions: { staleTime: 30_000, enabled: tab === "relay-proxy" },
  });

  const proxyQuery = useCustom<{ data: SecurityEvent[]; total: number }>({
    url: "/api/security-events",
    method: "get",
    config: { query: { rule_id: "BOT-PROXY", page_size: 50, page: 1 } },
    queryOptions: { staleTime: 30_000, enabled: tab === "relay-proxy" },
  });

  const overviewQuery = useCustom<StatsOverview>({
    url: "/api/stats/overview",
    method: "get",
    queryOptions: { staleTime: 30_000, enabled: tab === "relay-proxy" },
  });
  const { mutate: createPattern, mutation: createMutation } = useCustomMutation();
  const { mutate: togglePattern } = useCustomMutation();
  const creating = createMutation.isPending;
  const refetch = query.refetch;
  const isLoading = query.isLoading;

  // Bulletproof: Refine v5 useCustom's result.data shape can vary at runtime;
  // coerce to array so downstream .map/.filter/.some never crash.
  const rawPatterns = result?.data?.patterns;
  const patterns: BotPattern[] = Array.isArray(rawPatterns) ? rawPatterns : [];

  const filtered = useMemo(() => {
    const cfg = TABS.find((x) => x.key === tab);
    if (!cfg) return [];
    if (tab === "custom") return patterns.filter((p) => p.source === "custom");
    return patterns.filter((p) => p.tags?.includes(cfg.tag));
  }, [patterns, tab]);

  const onAdd = async () => {
    const v = await form.validateFields();
    createPattern(
      { url: "/api/bot-patterns", method: "post", values: v },
      {
        onSuccess: () => {
          message.success("OK");
          setOpen(false);
          form.resetFields();
          refetch();
        },
        onError: (err) => message.error(err.message),
      },
    );
  };

  const onToggle = (p: BotPattern) =>
    togglePattern(
      { url: `/api/bot-patterns/${p.id}`, method: "patch", values: { enabled: !p.enabled } },
      { onSuccess: () => refetch(), onError: (err) => message.error(err.message) },
    );

  const runTest = () => {
    const matches: TestMatch[] = [];
    for (const p of patterns) {
      try {
        const re = new RegExp(p.pattern);
        if (re.test(testUa)) {
          matches.push({ id: p.id, name: p.name, action: p.action });
        }
      } catch {
        // skip invalid regex stored on backend
      }
    }
    setTestResult(matches);
  };

  const relayProxyData = useMemo(() => {
    const relay = relayQuery.result?.data?.data ?? [];
    const proxy = proxyQuery.result?.data?.data ?? [];
    return [...relay, ...proxy]
      .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
      .slice(0, 100);
  }, [relayQuery.result, proxyQuery.result]);

  const statsOverview = overviewQuery.result?.data;

  const actionTagColor = (a: string): string =>
    ({ block: "red", log: "gold", allow: "green" }[a] ?? "default");

  const relayColumns: ColumnsType<SecurityEvent> = [
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
      render: (v: string) => (
        <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>{v}</span>
      ),
    },
    {
      title: t("botManagement.detectedIsp"),
      key: "isp",
      width: 160,
      render: (_: unknown, r: SecurityEvent) => r.geo_info?.isp ?? "—",
    },
    {
      title: t("botManagement.ruleTriggered"),
      dataIndex: "rule_id",
      width: 140,
      render: (v: string | null) =>
        v ? (
          <Tag style={{ fontSize: 11 }}>{v}</Tag>
        ) : (
          <span style={{ color: "#bfbfbf" }}>—</span>
        ),
    },
    {
      title: t("security.action"),
      dataIndex: "action",
      width: 90,
      render: (v: string) => <Tag color={v === "block" ? "red" : "default"}>{v}</Tag>,
    },
    {
      title: t("security.path"),
      dataIndex: "path",
      ellipsis: true,
      render: (v: string) => (
        <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 11 }} title={v}>{v}</span>
      ),
    },
  ];

  const columns: ColumnsType<BotPattern> = [
    { title: t("botManagement.id"), dataIndex: "id", width: 130, render: (v) => <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12, color: "#8c8c8c" }}>{v}</span> },
    { title: t("botManagement.name"), dataIndex: "name", render: (v) => <strong>{v}</strong> },
    { title: t("botManagement.pattern"), dataIndex: "pattern", ellipsis: true, render: (v) => <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 11 }}>{v}</span> },
    { title: t("botManagement.action"), dataIndex: "action", width: 90, render: (v) => <Tag color={actionTagColor(v)}>{v}</Tag> },
    { title: t("botManagement.tags"), dataIndex: "tags", width: 200, render: (v?: string[]) => <span style={{ fontSize: 11, color: "#8c8c8c" }}>{v?.join(", ")}</span> },
    {
      title: t("botManagement.status"),
      dataIndex: "enabled",
      width: 100,
      render: (_v, r) => (
        <Button size="small" type="link" onClick={() => onToggle(r)} style={{ color: r.enabled ? "#52c41a" : "#bfbfbf" }}>
          {r.enabled ? t("botManagement.enabled") : t("botManagement.disabled")}
        </Button>
      ),
    },
  ];

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <div>
          <Typography.Title level={4} style={{ margin: 0 }}>
            {t("botManagement.title")}
          </Typography.Title>
          <Typography.Text type="secondary">{t("botManagement.subtitle")}</Typography.Text>
        </div>
        <Button type="primary" onClick={() => setOpen(true)}>
          {t("botManagement.addPattern")}
        </Button>
      </Space>

      <Card size="small" title={t("botManagement.testUA")}>
        <Space.Compact style={{ width: "100%" }}>
          <Input value={testUa} onChange={(e) => setTestUa(e.target.value)} placeholder="Mozilla/5.0 ..." onPressEnter={runTest} />
          <Button type="primary" onClick={runTest}>
            {t("common.test")}
          </Button>
        </Space.Compact>
        {testResult !== null && (
          <div style={{ marginTop: 12 }}>
            {testResult.length === 0 ? (
              <Alert type="success" message={t("botManagement.noMatch")} showIcon />
            ) : (
              <Space direction="vertical" size={4} style={{ width: "100%" }}>
                {testResult.map((m) => (
                  <div key={m.id} style={{ fontSize: 13 }}>
                    <Tag color={actionTagColor(m.action)}>{m.action.toUpperCase()}</Tag>
                    <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>{m.id}</span> — {m.name}
                  </div>
                ))}
              </Space>
            )}
          </div>
        )}
      </Card>

      <Card size="small">
        <Tabs
          activeKey={tab}
          onChange={setTab}
          items={TABS.map((x) => ({
            key: x.key,
            label: (
              <span>
                {t(x.i18nKey)}{" "}
                {x.key !== "relay-proxy" && (
                  <Tag style={{ marginLeft: 4 }}>
                    {x.key === "custom"
                      ? patterns.filter((p) => p.source === "custom").length
                      : patterns.filter((p) => p.tags?.includes(x.tag)).length}
                  </Tag>
                )}
              </span>
            ),
          }))}
        />

        {tab === "relay-proxy" ? (
          <Space direction="vertical" size="middle" style={{ width: "100%" }}>
            <TopList
              title={t("botManagement.topIsps")}
              items={statsOverview?.top_isps}
              badgeColor="#1677ff"
            />
            <Alert
              type="info"
              showIcon
              message={t("botManagement.xffSpoof")}
              description={t("botManagement.xffSpoof") + " events use rule BOT-XFF-SPOOF. Relay/proxy events shown below."}
              style={{ marginBottom: 0 }}
            />
            <Table<SecurityEvent>
              rowKey="id"
              size="small"
              dataSource={relayProxyData}
              columns={relayColumns}
              loading={relayQuery.query.isLoading || proxyQuery.query.isLoading}
              pagination={false}
              locale={{ emptyText: t("botManagement.noRelayProxy") }}
              scroll={{ x: 800 }}
            />
          </Space>
        ) : (
          <Table
            rowKey="id"
            size="small"
            dataSource={filtered}
            columns={columns}
            loading={isLoading}
            pagination={false}
            locale={{ emptyText: t("botManagement.noPatterns") }}
          />
        )}
      </Card>

      <Modal
        title={t("botManagement.addPatternTitle")}
        open={open}
        onCancel={() => setOpen(false)}
        onOk={onAdd}
        confirmLoading={creating}
        okText={t("botManagement.confirmAdd")}
        cancelText={t("common.cancel")}
        destroyOnClose
      >
        <Form form={form} layout="vertical" initialValues={{ action: "block" }}>
          <Form.Item name="pattern" label={t("botManagement.patternRegex")} rules={[{ required: true }]}>
            <Input style={{ fontFamily: "ui-monospace, monospace" }} placeholder="(?i)\bMyBot\b" />
          </Form.Item>
          <Form.Item name="name" label={t("botManagement.nameRequired")} rules={[{ required: true }]}>
            <Input />
          </Form.Item>
          <Form.Item name="action" label={t("botManagement.actionField")}>
            <Select
              options={[
                { value: "block", label: t("botManagement.block") },
                { value: "log", label: t("botManagement.logOnly") },
                { value: "allow", label: t("botManagement.allowWhitelist") },
              ]}
            />
          </Form.Item>
          <Form.Item name="description" label={t("botManagement.description")}>
            <Input />
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  );
};
