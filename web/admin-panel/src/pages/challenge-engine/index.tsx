import {
  Card,
  Row,
  Col,
  Typography,
  Space,
  Button,
  Switch,
  Select,
  InputNumber,
  Input,
  Form,
  Alert,
  Tooltip,
  App,
} from "antd";
import {
  ReloadOutlined,
  SendOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  RocketOutlined,
  DatabaseOutlined,
} from "@ant-design/icons";
import { useCustom, useCustomMutation } from "@refinedev/core";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { KpiCard } from "../../components/kpi-card";

// ── Types ──────────────────────────────────────────────────────────────────────

interface ChallengeConfig {
  enabled: boolean;
  challenge_type: "js_challenge" | "pow" | "captcha";
  ttl_secs: number;
  cookie_name: string;
  same_site: "Strict" | "Lax" | "None";
  http_only: boolean;
  branding: { title: string; message: string };
  nonce_store: { capacity: number; gc_interval_secs: number };
}

interface ChallengeStats {
  issued: number;
  passed: number;
  failed: number;
  replays: number;
}

// ── Page ──────────────────────────────────────────────────────────────────────

export const ChallengeEnginePage: React.FC = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [form] = Form.useForm<ChallengeConfig>();
  const [autoRefresh, setAutoRefresh] = useState(true);
  const interval = autoRefresh ? 30_000 : (false as const);
  const [previewHtml, setPreviewHtml] = useState<string | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);

  // ── API: stats ────────────────────────────────────────────────────────────

  const statsQuery = useCustom<ChallengeStats>({
    url: "/api/challenge/stats",
    method: "get",
    queryOptions: { staleTime: 0, refetchInterval: interval },
  });
  const stats = statsQuery.result?.data;

  // ── API: config ───────────────────────────────────────────────────────────

  const configQuery = useCustom<ChallengeConfig>({
    url: "/api/challenge/config",
    method: "get",
    queryOptions: { staleTime: 60_000 },
  });

  useEffect(() => {
    const c = configQuery.result?.data;
    if (!c) return;
    form.setFieldsValue(c);
  }, [configQuery.result, form]);

  // ── API: save config ──────────────────────────────────────────────────────

  const { mutate: saveConfig, mutation: saveMutation } = useCustomMutation();
  const saving = saveMutation.isPending;

  const onSave = async () => {
    const v = await form.validateFields();
    saveConfig(
      { url: "/api/challenge/config", method: "put", values: v },
      {
        onSuccess: () => {
          message.success(t("challenge.configSaved"));
          configQuery.query.refetch();
        },
        onError: (err) => message.error(err.message),
      },
    );
  };

  // ── Preview ───────────────────────────────────────────────────────────────

  const onPreview = async () => {
    const v = form.getFieldsValue();
    setPreviewLoading(true);
    setPreviewHtml(null);
    try {
      const resp = await fetch("/api/challenge/preview", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ branding: v.branding }),
      });
      const text = await resp.text();
      setPreviewHtml(text);
    } catch {
      setPreviewHtml("<p style='color:red'>Preview unavailable</p>");
    } finally {
      setPreviewLoading(false);
    }
  };

  const httpOnly = Form.useWatch("http_only", form);

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      {/* Header */}
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <div>
          <Typography.Title level={4} style={{ margin: 0 }}>
            {t("challenge.title")}
          </Typography.Title>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {t("challenge.subtitle")}
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
            icon={<ReloadOutlined spin={statsQuery.query.isFetching} />}
            onClick={() => statsQuery.query.refetch()}
          >
            {t("common.refresh")}
          </Button>
        </Space>
      </Space>

      {/* KPI row */}
      {statsQuery.query.isError ? (
        <Alert
          type="warning"
          showIcon
          message={t("challenge.statsUnavailable")}
          description="GET /api/challenge/stats endpoint is not available."
        />
      ) : (
        <Row gutter={[16, 16]}>
          <Col xs={12} sm={6}>
            <KpiCard
              label={t("challenge.issued")}
              value={stats?.issued ?? "—"}
              icon={SendOutlined}
              color="blue"
              loading={statsQuery.query.isLoading}
            />
          </Col>
          <Col xs={12} sm={6}>
            <KpiCard
              label={t("challenge.passed")}
              value={stats?.passed ?? "—"}
              icon={CheckCircleOutlined}
              color="green"
              loading={statsQuery.query.isLoading}
            />
          </Col>
          <Col xs={12} sm={6}>
            <KpiCard
              label={t("challenge.failed")}
              value={stats?.failed ?? "—"}
              icon={CloseCircleOutlined}
              color="red"
              loading={statsQuery.query.isLoading}
            />
          </Col>
          <Col xs={12} sm={6}>
            <KpiCard
              label={t("challenge.replays")}
              value={stats?.replays ?? "—"}
              icon={ReloadOutlined}
              color="orange"
              loading={statsQuery.query.isLoading}
            />
          </Col>
        </Row>
      )}

      {/* Config form */}
      {configQuery.query.isError ? (
        <Alert
          type="warning"
          showIcon
          message={t("challenge.configUnavailable")}
          description="GET /api/challenge/config endpoint is not available."
        />
      ) : (
        <Form form={form} layout="vertical">
          {/* Mode selector */}
          <Card
            size="small"
            title={t("challenge.modeSelector")}
            loading={configQuery.query.isLoading}
            style={{ marginBottom: 16 }}
          >
            <Row gutter={16} align="middle">
              <Col xs={24} sm={6}>
                <Form.Item
                  name="enabled"
                  valuePropName="checked"
                  label={t("challenge.enabled")}
                  style={{ marginBottom: 0 }}
                >
                  <Switch />
                </Form.Item>
              </Col>
              <Col xs={24} sm={18}>
                <Form.Item
                  name="challenge_type"
                  label={t("challenge.challengeType")}
                  style={{ marginBottom: 0 }}
                >
                  <Select
                    style={{ width: 240 }}
                    options={[
                      { value: "js_challenge", label: "JS Challenge" },
                      {
                        value: "pow",
                        label: (
                          <Tooltip title={t("challenge.comingSoon")}>
                            <span style={{ color: "#bfbfbf" }}>
                              Proof of Work (Coming soon)
                            </span>
                          </Tooltip>
                        ),
                        disabled: true,
                      },
                      {
                        value: "captcha",
                        label: (
                          <Tooltip title={t("challenge.comingSoon")}>
                            <span style={{ color: "#bfbfbf" }}>
                              CAPTCHA (Coming soon)
                            </span>
                          </Tooltip>
                        ),
                        disabled: true,
                      },
                    ]}
                  />
                </Form.Item>
              </Col>
            </Row>
          </Card>

          {/* Token settings */}
          <Card
            size="small"
            title={t("challenge.tokenSettings")}
            loading={configQuery.query.isLoading}
            style={{ marginBottom: 16 }}
          >
            <Row gutter={16}>
              <Col xs={24} sm={8}>
                <Form.Item
                  name="ttl_secs"
                  label={t("challenge.ttlSecs")}
                  rules={[{ required: true }]}
                >
                  <InputNumber min={30} max={86400} style={{ width: "100%" }} />
                </Form.Item>
              </Col>
              <Col xs={24} sm={8}>
                <Form.Item
                  name="cookie_name"
                  label={t("challenge.cookieName")}
                  rules={[{ required: true }]}
                >
                  <Input placeholder="_waf_challenge" />
                </Form.Item>
              </Col>
              <Col xs={24} sm={8}>
                <Form.Item name="same_site" label={t("challenge.sameSite")}>
                  <Select
                    options={[
                      { value: "Strict", label: "Strict" },
                      { value: "Lax", label: "Lax" },
                      { value: "None", label: "None" },
                    ]}
                  />
                </Form.Item>
              </Col>
            </Row>
            <Form.Item
              name="http_only"
              valuePropName="checked"
              label={t("challenge.httpOnly")}
              style={{ marginBottom: 0 }}
            >
              <Switch />
            </Form.Item>
            {httpOnly && (
              <Alert
                type="warning"
                showIcon
                message={t("challenge.httpOnlyWarning")}
                style={{ marginTop: 12 }}
              />
            )}
          </Card>

          {/* Branding */}
          <Card
            size="small"
            title={t("challenge.branding")}
            loading={configQuery.query.isLoading}
            style={{ marginBottom: 16 }}
            extra={
              <Button
                size="small"
                icon={<RocketOutlined />}
                loading={previewLoading}
                onClick={onPreview}
              >
                {t("challenge.preview")}
              </Button>
            }
          >
            <Row gutter={16}>
              <Col xs={24} sm={previewHtml ? 12 : 24}>
                <Form.Item
                  name={["branding", "title"]}
                  label={t("challenge.brandingTitle")}
                >
                  <Input placeholder="Security Check" />
                </Form.Item>
                <Form.Item
                  name={["branding", "message"]}
                  label={t("challenge.brandingMessage")}
                >
                  <Input.TextArea
                    rows={3}
                    placeholder="Please wait while we verify your browser..."
                  />
                </Form.Item>
              </Col>
              {previewHtml && (
                <Col xs={24} sm={12}>
                  <iframe
                    title="challenge-preview"
                    srcDoc={previewHtml}
                    style={{
                      width: "100%",
                      height: 200,
                      border: "1px solid #f0f0f0",
                      borderRadius: 6,
                    }}
                    sandbox="allow-scripts"
                  />
                </Col>
              )}
            </Row>
          </Card>

          {/* Nonce store */}
          <Card
            size="small"
            title={t("challenge.nonceStore")}
            loading={configQuery.query.isLoading}
            style={{ marginBottom: 16 }}
            extra={<DatabaseOutlined style={{ color: "#8c8c8c" }} />}
          >
            <Row gutter={16}>
              <Col xs={24} sm={12}>
                <Form.Item
                  name={["nonce_store", "capacity"]}
                  label={t("challenge.nonceCapacity")}
                >
                  <InputNumber min={1} style={{ width: "100%" }} />
                </Form.Item>
              </Col>
              <Col xs={24} sm={12}>
                <Form.Item
                  name={["nonce_store", "gc_interval_secs"]}
                  label={t("challenge.nonceGcInterval")}
                >
                  <InputNumber min={1} style={{ width: "100%" }} />
                </Form.Item>
              </Col>
            </Row>
          </Card>

          <Button type="primary" loading={saving} onClick={onSave}>
            {t("common.save")}
          </Button>
        </Form>
      )}
    </Space>
  );
};
