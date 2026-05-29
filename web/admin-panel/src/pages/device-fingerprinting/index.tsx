import {
  Alert,
  Button,
  Card,
  Col,
  Form,
  InputNumber,
  Row,
  Select,
  Slider,
  Space,
  Switch,
  Table,
  Tabs,
  Tag,
  Typography,
  App,
  Input,
} from "antd";
import type { ColumnsType } from "antd/es/table";
import { ScanOutlined, SaveOutlined, ReloadOutlined } from "@ant-design/icons";
import { useCustom, useCustomMutation } from "@refinedev/core";
import { useTranslation } from "react-i18next";
import { useEffect, useRef, useState } from "react";
import { fmtDateTime } from "../../utils/format";

interface DeviceFpConfig {
  enabled: boolean;
  capture: {
    tls: { enabled: boolean; algorithms: string[] };
    h2: { enabled: boolean; hash: string };
  };
  store: { backend: "memory" | "redis"; redis_url?: string; ttl_secs: number };
  providers: {
    ip_hopping: { enabled: boolean; signal_weight: number; window_secs: number; max_distinct_ips: number };
    fp_conflict: { enabled: boolean; signal_weight: number };
    ua_entropy: { enabled: boolean; signal_weight: number; min_entropy_x100: number };
    ua_blocklist: { enabled: boolean; signal_weight: number; patterns: string[] };
    h2_anomaly: { enabled: boolean; signal_weight: number };
  };
  behavior: {
    window_size: number;
    actor_ttl_secs: number;
    burst_interval: { enabled: boolean; threshold_ms: number; min_consecutive: number; risk_delta: number };
    regularity: { enabled: boolean; min_samples: number; cv_threshold: number; min_mean_ms: number; risk_delta: number };
    zero_depth: { enabled: boolean; min_samples: number; critical_hits_required: number; risk_delta: number };
    missing_referer: { enabled: boolean; risk_delta: number };
  };
}

interface RecentFp {
  fp: string;
  ja3?: string;
  ja4?: string;
  ua?: string;
  distinct_ips_24h: number;
  first_seen: string;
  last_seen: string;
}

const DEFAULT_CONFIG: DeviceFpConfig = {
  enabled: true,
  capture: { tls: { enabled: true, algorithms: ["ja3", "ja4"] }, h2: { enabled: true, hash: "akamai" } },
  store: { backend: "memory", ttl_secs: 3600 },
  providers: {
    ip_hopping: { enabled: true, signal_weight: 20, window_secs: 86400, max_distinct_ips: 5 },
    fp_conflict: { enabled: true, signal_weight: 30 },
    ua_entropy: { enabled: true, signal_weight: 10, min_entropy_x100: 250 },
    ua_blocklist: { enabled: true, signal_weight: 25, patterns: [] },
    h2_anomaly: { enabled: true, signal_weight: 15 },
  },
  behavior: {
    window_size: 16,
    actor_ttl_secs: 600,
    burst_interval: { enabled: true, threshold_ms: 50, min_consecutive: 5, risk_delta: 15 },
    regularity: { enabled: true, min_samples: 6, cv_threshold: 0.15, min_mean_ms: 100, risk_delta: 10 },
    zero_depth: { enabled: true, min_samples: 4, critical_hits_required: 3, risk_delta: 10 },
    missing_referer: { enabled: true, risk_delta: 5 },
  },
};

const SectionCard: React.FC<{ title: React.ReactNode; children: React.ReactNode }> = ({ title, children }) => (
  <Card size="small" title={title} style={{ marginBottom: 12 }}>
    {children}
  </Card>
);

export const DeviceFingerprintingPage: React.FC = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [form] = Form.useForm<DeviceFpConfig>();
  const [saving, setSaving] = useState(false);
  const [notAvailable, setNotAvailable] = useState(false);
  const dirtyRef = useRef(false);
  const [storeBackend, setStoreBackend] = useState<"memory" | "redis">("memory");

  const configQuery = useCustom<DeviceFpConfig>({
    url: "/api/device-fp/config",
    method: "get",
    queryOptions: { staleTime: 15_000, retry: false },
    errorNotification: false,
  });

  const recentQuery = useCustom<{ data: RecentFp[]; total: number }>({
    url: "/api/device-fp/recent",
    method: "get",
    config: { query: { limit: 50 } },
    queryOptions: { staleTime: 10_000, retry: false },
    errorNotification: false,
  });

  const { mutate: saveMutate } = useCustomMutation();

  useEffect(() => {
    const raw = configQuery.result?.data;
    if (!raw) return;
    const cfg = (raw as { data?: DeviceFpConfig }).data ?? raw as DeviceFpConfig;
    if (cfg && cfg.enabled !== undefined) {
      form.setFieldsValue(cfg);
      setStoreBackend(cfg.store?.backend ?? "memory");
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
    setSaving(true);
    saveMutate(
      { url: "/api/device-fp/config", method: "put", values: vals },
      {
        onSuccess: () => { message.success(t("deviceFp.saved")); dirtyRef.current = false; configQuery.query.refetch(); },
        onError: () => message.error("Failed to save config"),
        onSettled: () => setSaving(false),
      }
    );
  };

  const recentData: RecentFp[] = (() => {
    const raw = recentQuery.result?.data;
    if (!raw) return [];
    if (Array.isArray(raw)) return raw;
    if (Array.isArray((raw as { data: RecentFp[] }).data)) return (raw as { data: RecentFp[] }).data;
    return [];
  })();

  const recentColumns: ColumnsType<RecentFp> = [
    { title: t("deviceFp.fp"), dataIndex: "fp", render: v => <Typography.Text code ellipsis style={{ maxWidth: 120 }}>{v?.slice(0, 16)}...</Typography.Text> },
    { title: "JA3/JA4", render: (_, r) => <Tag>{r.ja4 ?? r.ja3 ?? "—"}</Tag>, width: 120 },
    { title: t("deviceFp.ua"), dataIndex: "ua", ellipsis: true },
    { title: t("deviceFp.distinctIps"), dataIndex: "distinct_ips_24h", width: 120 },
    { title: t("deviceFp.firstSeen"), dataIndex: "first_seen", width: 160, render: v => fmtDateTime(v) },
    { title: t("deviceFp.lastSeen"), dataIndex: "last_seen", width: 160, render: v => fmtDateTime(v) },
  ];

  return (
    <Space direction="vertical" style={{ width: "100%" }}>
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <div>
          <Typography.Title level={4} style={{ margin: 0 }}>
            <ScanOutlined style={{ marginRight: 8 }} />{t("deviceFp.title")}
          </Typography.Title>
          <Typography.Text type="secondary">{t("deviceFp.subtitle")}</Typography.Text>
        </div>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={() => configQuery.query.refetch()}>{t("common.refresh")}</Button>
          <Button type="primary" icon={<SaveOutlined />} loading={saving} onClick={handleSave}>{t("deviceFp.save")}</Button>
        </Space>
      </Space>

      {notAvailable && (
        <Alert
          type="warning"
          showIcon
          message={t("deviceFp.unavailable")}
          description="UI is fully functional — connect a backend to persist changes."
        />
      )}

      <Form form={form} layout="vertical" onValuesChange={() => { dirtyRef.current = true; }}>
        <Tabs
          items={[
            {
              key: "capture",
              label: t("deviceFp.captureTab"),
              children: (
                <Row gutter={[16, 16]}>
                  <Col xs={24} lg={12}>
                    <SectionCard title={t("deviceFp.enabled")}>
                      <Form.Item name="enabled" valuePropName="checked" noStyle>
                        <Switch checkedChildren="On" unCheckedChildren="Off" />
                      </Form.Item>
                    </SectionCard>

                    <SectionCard title={t("deviceFp.tlsCapture")}>
                      <Row gutter={12} align="middle">
                        <Col span={8}>
                          <Form.Item name={["capture", "tls", "enabled"]} valuePropName="checked" label="Enabled" noStyle>
                            <Switch size="small" />
                          </Form.Item>
                        </Col>
                        <Col span={16}>
                          <Form.Item name={["capture", "tls", "algorithms"]} label={t("deviceFp.algorithms")}>
                            <Select mode="multiple" options={[{ value: "ja3", label: "JA3" }, { value: "ja4", label: "JA4" }]} />
                          </Form.Item>
                        </Col>
                      </Row>
                    </SectionCard>

                    <SectionCard title={t("deviceFp.h2Capture")}>
                      <Row gutter={12} align="middle">
                        <Col span={8}>
                          <Form.Item name={["capture", "h2", "enabled"]} valuePropName="checked" label="Enabled">
                            <Switch size="small" />
                          </Form.Item>
                        </Col>
                        <Col span={16}>
                          <Form.Item name={["capture", "h2", "hash"]} label={t("deviceFp.hash")}>
                            <Select options={[{ value: "akamai", label: "Akamai H2" }]} />
                          </Form.Item>
                        </Col>
                      </Row>
                    </SectionCard>

                    <SectionCard title={t("deviceFp.store")}>
                      <Row gutter={12}>
                        <Col span={12}>
                          <Form.Item name={["store", "backend"]} label="Backend">
                            <Select options={[{ value: "memory", label: "Memory" }, { value: "redis", label: "Redis" }]} onChange={v => setStoreBackend(v)} />
                          </Form.Item>
                        </Col>
                        <Col span={12}>
                          <Form.Item name={["store", "ttl_secs"]} label={t("deviceFp.ttlSecs")}>
                            <InputNumber min={60} style={{ width: "100%" }} />
                          </Form.Item>
                        </Col>
                        {storeBackend === "redis" && (
                          <Col span={24}>
                            <Form.Item name={["store", "redis_url"]} label="Redis URL">
                              <Input placeholder="redis://127.0.0.1:6379" />
                            </Form.Item>
                          </Col>
                        )}
                      </Row>
                    </SectionCard>
                  </Col>

                  <Col xs={24} lg={12}>
                    <SectionCard title={t("deviceFp.providers")}>
                      {(["ip_hopping", "fp_conflict", "ua_entropy", "ua_blocklist", "h2_anomaly"] as const).map(prov => (
                        <Card key={prov} size="small" style={{ marginBottom: 8 }} title={
                          <Space>
                            <Form.Item name={["providers", prov, "enabled"]} valuePropName="checked" noStyle>
                              <Switch size="small" />
                            </Form.Item>
                            <span>{prov}</span>
                          </Space>
                        }>
                          <Row gutter={12}>
                            <Col span={12}>
                              <Form.Item name={["providers", prov, "signal_weight"]} label={t("deviceFp.signalWeight")}>
                                <Slider min={0} max={50} />
                              </Form.Item>
                            </Col>
                            {prov === "ip_hopping" && (
                              <>
                                <Col span={12}>
                                  <Form.Item name={["providers", "ip_hopping", "window_secs"]} label={t("deviceFp.windowSecs")}>
                                    <InputNumber min={3600} style={{ width: "100%" }} />
                                  </Form.Item>
                                </Col>
                                <Col span={12}>
                                  <Form.Item name={["providers", "ip_hopping", "max_distinct_ips"]} label={t("deviceFp.maxDistinctIps")}>
                                    <InputNumber min={2} style={{ width: "100%" }} />
                                  </Form.Item>
                                </Col>
                              </>
                            )}
                            {prov === "ua_entropy" && (
                              <Col span={12}>
                                <Form.Item name={["providers", "ua_entropy", "min_entropy_x100"]} label={t("deviceFp.minEntropy")}>
                                  <InputNumber min={0} max={1000} style={{ width: "100%" }} />
                                </Form.Item>
                              </Col>
                            )}
                          </Row>
                        </Card>
                      ))}
                    </SectionCard>
                  </Col>

                  <Col xs={24}>
                    <Card title={t("deviceFp.recentFps")} size="small" extra={<Button size="small" onClick={() => recentQuery.query.refetch()}><ReloadOutlined /></Button>}>
                      <Table
                        dataSource={recentData}
                        columns={recentColumns}
                        rowKey="fp"
                        size="small"
                        pagination={{ pageSize: 10 }}
                        loading={recentQuery.query.isLoading}
                      />
                    </Card>
                  </Col>
                </Row>
              ),
            },
            {
              key: "behavior",
              label: t("deviceFp.behaviorTab"),
              children: (
                <Row gutter={[16, 16]}>
                  <Col xs={24} lg={12}>
                    <SectionCard title="Global">
                      <Row gutter={12}>
                        <Col span={12}>
                          <Form.Item name={["behavior", "window_size"]} label={t("deviceFp.windowSize")}>
                            <InputNumber min={4} max={64} style={{ width: "100%" }} />
                          </Form.Item>
                        </Col>
                        <Col span={12}>
                          <Form.Item name={["behavior", "actor_ttl_secs"]} label={t("deviceFp.actorTtl")}>
                            <InputNumber min={60} style={{ width: "100%" }} />
                          </Form.Item>
                        </Col>
                      </Row>
                    </SectionCard>

                    <SectionCard title={t("deviceFp.burstInterval")}>
                      <Row gutter={12}>
                        <Col span={8}>
                          <Form.Item name={["behavior", "burst_interval", "enabled"]} valuePropName="checked" label="Enabled">
                            <Switch size="small" />
                          </Form.Item>
                        </Col>
                        <Col span={8}>
                          <Form.Item name={["behavior", "burst_interval", "threshold_ms"]} label={t("deviceFp.thresholdMs")}>
                            <InputNumber min={10} style={{ width: "100%" }} />
                          </Form.Item>
                        </Col>
                        <Col span={8}>
                          <Form.Item name={["behavior", "burst_interval", "min_consecutive"]} label={t("deviceFp.minConsecutive")}>
                            <InputNumber min={2} style={{ width: "100%" }} />
                          </Form.Item>
                        </Col>
                        <Col span={24}>
                          <Form.Item name={["behavior", "burst_interval", "risk_delta"]} label={t("deviceFp.riskDelta")}>
                            <Slider min={0} max={50} />
                          </Form.Item>
                        </Col>
                      </Row>
                    </SectionCard>
                  </Col>

                  <Col xs={24} lg={12}>
                    <SectionCard title={t("deviceFp.regularity")}>
                      <Row gutter={12}>
                        <Col span={8}>
                          <Form.Item name={["behavior", "regularity", "enabled"]} valuePropName="checked" label="Enabled">
                            <Switch size="small" />
                          </Form.Item>
                        </Col>
                        <Col span={8}>
                          <Form.Item name={["behavior", "regularity", "min_samples"]} label={t("deviceFp.minSamples")}>
                            <InputNumber min={3} style={{ width: "100%" }} />
                          </Form.Item>
                        </Col>
                        <Col span={8}>
                          <Form.Item name={["behavior", "regularity", "cv_threshold"]} label={t("deviceFp.cvThreshold")}>
                            <InputNumber min={0.01} max={1.0} step={0.01} style={{ width: "100%" }} />
                          </Form.Item>
                        </Col>
                        <Col span={24}>
                          <Form.Item name={["behavior", "regularity", "risk_delta"]} label={t("deviceFp.riskDelta")}>
                            <Slider min={0} max={50} />
                          </Form.Item>
                        </Col>
                      </Row>
                    </SectionCard>

                    <SectionCard title={t("deviceFp.zeroDepth")}>
                      <Row gutter={12}>
                        <Col span={8}>
                          <Form.Item name={["behavior", "zero_depth", "enabled"]} valuePropName="checked" label="Enabled">
                            <Switch size="small" />
                          </Form.Item>
                        </Col>
                        <Col span={8}>
                          <Form.Item name={["behavior", "zero_depth", "min_samples"]} label={t("deviceFp.minSamples")}>
                            <InputNumber min={2} style={{ width: "100%" }} />
                          </Form.Item>
                        </Col>
                        <Col span={8}>
                          <Form.Item name={["behavior", "zero_depth", "critical_hits_required"]} label={t("deviceFp.criticalHits")}>
                            <InputNumber min={1} style={{ width: "100%" }} />
                          </Form.Item>
                        </Col>
                        <Col span={24}>
                          <Form.Item name={["behavior", "zero_depth", "risk_delta"]} label={t("deviceFp.riskDelta")}>
                            <Slider min={0} max={50} />
                          </Form.Item>
                        </Col>
                      </Row>
                    </SectionCard>

                    <SectionCard title={t("deviceFp.missingReferer")}>
                      <Row gutter={12}>
                        <Col span={8}>
                          <Form.Item name={["behavior", "missing_referer", "enabled"]} valuePropName="checked" label="Enabled">
                            <Switch size="small" />
                          </Form.Item>
                        </Col>
                        <Col span={24}>
                          <Form.Item name={["behavior", "missing_referer", "risk_delta"]} label={t("deviceFp.riskDelta")}>
                            <Slider min={0} max={50} />
                          </Form.Item>
                        </Col>
                      </Row>
                    </SectionCard>
                  </Col>
                </Row>
              ),
            },
          ]}
        />
      </Form>
    </Space>
  );
};
