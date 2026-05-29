import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
  Form,
  Input,
  InputNumber,
  Row,
  Slider,
  Space,
  Switch,
  Table,
  Tabs,
  Tag,
  Typography,
  App,
} from "antd";
import type { ColumnsType } from "antd/es/table";
import { BranchesOutlined, SaveOutlined, ReloadOutlined, SyncOutlined } from "@ant-design/icons";
import { useCustom, useCustomMutation } from "@refinedev/core";
import { useTranslation } from "react-i18next";
import { useEffect, useState } from "react";
import { fmtDateTime } from "../../utils/format";

interface IntelFeedStatus {
  tor: { entry_count: number; last_refresh_ts?: string; last_error?: string };
  asn: { entry_count: number; last_refresh_ts?: string; last_error?: string };
  datacenter: { entry_count: number; last_refresh_ts?: string; last_error?: string };
}

interface RelayConfig {
  enabled: boolean;
  providers: {
    asn_classifier: { enabled: boolean; risk_weight: number };
    tor_exit: { enabled: boolean; risk_weight: number };
    datacenter: { enabled: boolean; risk_weight: number };
    proxy_chain: { enabled: boolean; risk_weight: number };
    xff_validator: { enabled: boolean; risk_weight: number; max_chain_depth: number; reject_private_in_chain: boolean };
  };
  trusted_proxies: string[];
}

interface TestResult {
  provider_verdicts: Array<{ provider: string; triggered: boolean; risk_delta: number; reason?: string }>;
  total_risk_delta: number;
}

const DEFAULT_CONFIG: RelayConfig = {
  enabled: true,
  providers: {
    asn_classifier: { enabled: true, risk_weight: 15 },
    tor_exit: { enabled: true, risk_weight: 25 },
    datacenter: { enabled: true, risk_weight: 10 },
    proxy_chain: { enabled: true, risk_weight: 15 },
    xff_validator: { enabled: true, risk_weight: 10, max_chain_depth: 3, reject_private_in_chain: false },
  },
  trusted_proxies: [],
};

export const RelayIntelPage: React.FC = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [form] = Form.useForm<RelayConfig>();
  const [trustedInput, setTrustedInput] = useState("");
  const [trustedCidrs, setTrustedCidrs] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [notAvailable, setNotAvailable] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [testResult, setTestResult] = useState<TestResult | null>(null);
  const [testLoading, setTestLoading] = useState(false);
  const [testForm] = Form.useForm<{ client_ip: string; xff_chain: string; user_agent: string }>();

  const configQuery = useCustom<RelayConfig>({
    url: "/api/relay/config",
    method: "get",
    queryOptions: { staleTime: 15_000, retry: false },
    errorNotification: false,
  });

  const statusQuery = useCustom<IntelFeedStatus>({
    url: "/api/relay/intel/status",
    method: "get",
    queryOptions: { staleTime: 30_000, retry: false },
    errorNotification: false,
  });

  const { mutate: saveMutate } = useCustomMutation();
  const { mutate: refreshMutate } = useCustomMutation();
  const { mutate: testMutate } = useCustomMutation();

  useEffect(() => {
    const raw = configQuery.result?.data;
    if (!raw) return;
    const cfg = (raw as { data?: RelayConfig }).data ?? raw as RelayConfig;
    if (cfg && cfg.providers !== undefined) {
      form.setFieldsValue(cfg);
      setTrustedCidrs(cfg.trusted_proxies ?? []);
      setNotAvailable(false);
    } else {
      setNotAvailable(true);
      form.setFieldsValue(DEFAULT_CONFIG);
    }
  }, [configQuery.result]);

  useEffect(() => {
    if (configQuery.query.isError) {
      setNotAvailable(true);
      form.setFieldsValue(DEFAULT_CONFIG);
    }
  }, [configQuery.query.isError]);

  const handleSave = async () => {
    const vals = await form.validateFields();
    vals.trusted_proxies = trustedCidrs;
    setSaving(true);
    saveMutate(
      { url: "/api/relay/config", method: "put", values: vals },
      {
        onSuccess: () => { message.success(t("relay.saved")); configQuery.query.refetch(); },
        onError: () => message.error("Failed to save"),
        onSettled: () => setSaving(false),
      }
    );
  };

  const handleRefreshFeeds = () => {
    setRefreshing(true);
    refreshMutate(
      { url: "/api/relay/intel/refresh", method: "post", values: {} },
      {
        onSuccess: (result) => {
          const r = result?.data as { tor_loaded?: number; asn_loaded?: number };
          message.success(`Tor: ${r?.tor_loaded ?? "?"} entries, ASN: ${r?.asn_loaded ?? "?"} entries`);
          statusQuery.query.refetch();
        },
        onError: () => message.error("Refresh failed"),
        onSettled: () => setRefreshing(false),
      }
    );
  };

  const handleTest = async () => {
    const vals = await testForm.validateFields();
    setTestLoading(true);
    testMutate(
      {
        url: "/api/relay/test",
        method: "post",
        values: {
          client_ip: vals.client_ip,
          xff_chain: vals.xff_chain ? vals.xff_chain.split(",").map(s => s.trim()) : [],
          user_agent: vals.user_agent,
        },
      },
      {
        onSuccess: (r) => setTestResult(r?.data as TestResult),
        onError: () => message.error("Test failed"),
        onSettled: () => setTestLoading(false),
      }
    );
  };

  const status = (() => {
    const raw = statusQuery.result?.data;
    if (!raw) return null;
    return (raw as { data?: IntelFeedStatus }).data ?? raw as IntelFeedStatus;
  })();

  const verdictColumns: ColumnsType<{ provider: string; triggered: boolean; risk_delta: number; reason?: string }> = [
    { title: "Provider", dataIndex: "provider" },
    { title: "Triggered", dataIndex: "triggered", render: v => <Tag color={v ? "red" : "green"}>{v ? "Yes" : "No"}</Tag> },
    { title: "Risk Delta", dataIndex: "risk_delta", render: v => <Tag color={v > 0 ? "orange" : "default"}>+{v}</Tag> },
    { title: "Reason", dataIndex: "reason", render: v => v ?? "—" },
  ];

  const providerNames = ["asn_classifier", "tor_exit", "datacenter", "proxy_chain", "xff_validator"] as const;

  return (
    <Space direction="vertical" style={{ width: "100%" }}>
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <div>
          <Typography.Title level={4} style={{ margin: 0 }}>
            <BranchesOutlined style={{ marginRight: 8 }} />{t("relay.title")}
          </Typography.Title>
          <Typography.Text type="secondary">{t("relay.subtitle")}</Typography.Text>
        </div>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={() => configQuery.query.refetch()}>{t("common.refresh")}</Button>
          <Button type="primary" icon={<SaveOutlined />} loading={saving} onClick={handleSave}>{t("relay.save")}</Button>
        </Space>
      </Space>

      {notAvailable && (
        <Alert type="warning" showIcon message={t("relay.unavailable")} description="UI is functional — connect a backend to persist changes." />
      )}

      <Form form={form} layout="vertical">
        <Tabs items={[
          {
            key: "feeds",
            label: t("relay.feedsTab"),
            children: (
              <Row gutter={[16, 16]}>
                <Col span={24} style={{ textAlign: "right" }}>
                  <Button icon={<SyncOutlined />} loading={refreshing} onClick={handleRefreshFeeds}>{t("relay.refreshNow")}</Button>
                </Col>
                {(["tor", "asn", "datacenter"] as const).map(feed => {
                  const s = status?.[feed];
                  return (
                    <Col xs={24} md={8} key={feed}>
                      <Card
                        size="small"
                        title={feed === "tor" ? t("relay.torFeed") : feed === "asn" ? t("relay.asnFeed") : t("relay.datacenterFeed")}
                      >
                        {s?.last_error && <Alert type="error" message={s.last_error} style={{ marginBottom: 8 }} />}
                        <Descriptions column={1} size="small">
                          <Descriptions.Item label={t("relay.entryCount")}>{s?.entry_count ?? "—"}</Descriptions.Item>
                          <Descriptions.Item label={t("relay.lastRefresh")}>{s?.last_refresh_ts ? fmtDateTime(s.last_refresh_ts) : "—"}</Descriptions.Item>
                        </Descriptions>
                      </Card>
                    </Col>
                  );
                })}
              </Row>
            ),
          },
          {
            key: "providers",
            label: t("relay.providersTab"),
            children: (
              <Row gutter={[16, 16]}>
                {providerNames.map(prov => (
                  <Col xs={24} md={12} key={prov}>
                    <Card size="small" title={
                      <Space>
                        <Form.Item name={["providers", prov, "enabled"]} valuePropName="checked" noStyle>
                          <Switch size="small" />
                        </Form.Item>
                        <span>{prov}</span>
                      </Space>
                    }>
                      <Form.Item name={["providers", prov, "risk_weight"]} label={t("relay.riskWeight")}>
                        <Slider min={0} max={50} />
                      </Form.Item>
                      {prov === "xff_validator" && (
                        <Row gutter={12}>
                          <Col span={12}>
                            <Form.Item name={["providers", "xff_validator", "max_chain_depth"]} label={t("relay.maxChainDepth")}>
                              <InputNumber min={1} max={10} style={{ width: "100%" }} />
                            </Form.Item>
                          </Col>
                          <Col span={12}>
                            <Form.Item name={["providers", "xff_validator", "reject_private_in_chain"]} valuePropName="checked" label={t("relay.rejectPrivate")}>
                              <Switch size="small" />
                            </Form.Item>
                          </Col>
                        </Row>
                      )}
                    </Card>
                  </Col>
                ))}
              </Row>
            ),
          },
          {
            key: "trusted",
            label: t("relay.trustedProxiesTab"),
            children: (
              <Card size="small" title={t("relay.trustedCidrs")}>
                <Space direction="vertical" style={{ width: "100%" }}>
                  <Space.Compact style={{ width: "100%" }}>
                    <Input
                      placeholder="10.0.0.0/8"
                      value={trustedInput}
                      onChange={e => setTrustedInput(e.target.value)}
                      onPressEnter={() => {
                        if (trustedInput.trim()) {
                          setTrustedCidrs(prev => [...prev, trustedInput.trim()]);
                          setTrustedInput("");
                        }
                      }}
                    />
                    <Button onClick={() => {
                      if (trustedInput.trim()) {
                        setTrustedCidrs(prev => [...prev, trustedInput.trim()]);
                        setTrustedInput("");
                      }
                    }}>{t("common.add")}</Button>
                  </Space.Compact>
                  <div>
                    {trustedCidrs.map(cidr => (
                      <Tag key={cidr} closable onClose={() => setTrustedCidrs(prev => prev.filter(c => c !== cidr))} style={{ marginBottom: 4 }}>
                        {cidr}
                      </Tag>
                    ))}
                  </div>
                </Space>
              </Card>
            ),
          },
          {
            key: "test",
            label: t("relay.testTab"),
            children: (
              <Row gutter={[16, 16]}>
                <Col xs={24} md={12}>
                  <Card size="small" title={t("relay.testTab")}>
                    <Form form={testForm} layout="vertical">
                      <Form.Item name="client_ip" label={t("relay.testClientIp")} rules={[{ required: true }]}>
                        <Input placeholder="1.2.3.4" />
                      </Form.Item>
                      <Form.Item name="xff_chain" label={t("relay.testXffChain")}>
                        <Input placeholder="10.0.0.1, 203.0.113.1" />
                      </Form.Item>
                      <Form.Item name="user_agent" label={t("relay.testUserAgent")}>
                        <Input placeholder="Mozilla/5.0..." />
                      </Form.Item>
                      <Button type="primary" loading={testLoading} onClick={handleTest}>{t("relay.testRun")}</Button>
                    </Form>
                  </Card>
                </Col>
                <Col xs={24} md={12}>
                  {testResult && (
                    <Card size="small" title={t("relay.verdicts")}>
                      <Table
                        dataSource={testResult.provider_verdicts}
                        columns={verdictColumns}
                        rowKey="provider"
                        size="small"
                        pagination={false}
                      />
                      <div style={{ marginTop: 12 }}>
                        <Typography.Text strong>{t("relay.totalRiskDelta")}: </Typography.Text>
                        <Tag color={testResult.total_risk_delta > 0 ? "red" : "green"}>+{testResult.total_risk_delta}</Tag>
                      </div>
                    </Card>
                  )}
                </Col>
              </Row>
            ),
          },
        ]} />
      </Form>
    </Space>
  );
};
