import {
  Card,
  Form,
  Input,
  InputNumber,
  Select,
  Switch,
  Button,
  Space,
  Alert,
  Typography,
  Statistic,
  Row,
  Col,
  App,
} from "antd";
import { CheckCircleOutlined, WarningOutlined } from "@ant-design/icons";
import { useCustom, useCustomMutation } from "@refinedev/core";
import { useEffect } from "react";
import { useTranslation } from "react-i18next";

interface CrowdsecStatus {
  enabled: boolean;
  lapi_url?: string;
  connection_msg?: string;
  cache_stats?: { total_cached: number; hit_rate_pct: number };
}

interface CrowdsecConfig {
  enabled?: boolean;
  mode?: string;
  lapi_url?: string;
  api_key_set?: boolean;
  appsec_key_set?: boolean;
  update_frequency_secs?: number;
  fallback_action?: string;
  appsec_endpoint?: string;
}

interface CrowdsecForm {
  enabled: boolean;
  mode: string;
  lapi_url: string;
  api_key?: string;
  update_frequency_secs: number;
  fallback_action: string;
  appsec_endpoint?: string;
  appsec_key?: string;
}

interface TestResult {
  success: boolean;
  message: string;
}

export const CrowdsecSettingsPage: React.FC = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [form] = Form.useForm<CrowdsecForm>();

  const statusQuery = useCustom<CrowdsecStatus>({
    url: "/api/crowdsec/status",
    method: "get",
    queryOptions: { staleTime: 5_000, refetchInterval: 10_000 },
  });
  const configQuery = useCustom<CrowdsecConfig>({
    url: "/api/crowdsec/config",
    method: "get",
    queryOptions: { staleTime: 60_000 },
  });

  const { mutate: save, mutation: saveMutation } = useCustomMutation();
  const { mutate: testConn, mutation: testMutation } = useCustomMutation<TestResult>();
  const saving = saveMutation.isPending;
  const testing = testMutation.isPending;
  const testData = testMutation.data;
  const resetTest = testMutation.reset;

  // Sync server config into form once on first fetch.
  useEffect(() => {
    const c = configQuery.result?.data;
    if (!c) return;
    form.setFieldsValue({
      enabled: c.enabled ?? false,
      mode: c.mode ?? "bouncer",
      lapi_url: c.lapi_url ?? "http://127.0.0.1:8080",
      update_frequency_secs: c.update_frequency_secs ?? 10,
      fallback_action: c.fallback_action ?? "allow",
      appsec_endpoint: c.appsec_endpoint ?? "",
    });
  }, [configQuery.result, form]);

  const onSave = async () => {
    const v = await form.validateFields();
    const payload: Record<string, unknown> = {
      enabled: v.enabled,
      mode: v.mode,
      lapi_url: v.lapi_url,
      update_frequency_secs: v.update_frequency_secs,
      fallback_action: v.fallback_action,
    };
    if (v.api_key) payload.api_key = v.api_key;
    if (v.appsec_endpoint) payload.appsec_endpoint = v.appsec_endpoint;
    if (v.appsec_key) payload.appsec_key = v.appsec_key;

    save(
      { url: "/api/crowdsec/config", method: "put", values: payload },
      {
        onSuccess: () => {
          message.success("Saved. Restart prx-waf to apply.");
          statusQuery.query.refetch();
          configQuery.query.refetch();
        },
        onError: (err) => message.error(err.message),
      },
    );
  };

  const onTest = async () => {
    const v = form.getFieldsValue();
    resetTest();
    testConn({
      url: "/api/crowdsec/test",
      method: "post",
      values: { lapi_url: v.lapi_url, ...(v.api_key ? { api_key: v.api_key } : {}) },
    });
  };

  const s = statusQuery.result?.data;
  const c = configQuery.result?.data;
  const mode = Form.useWatch("mode", form);

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Typography.Title level={4}>{t("crowdsec.title")}</Typography.Title>

      <Alert
        type={s?.enabled ? "success" : "warning"}
        showIcon
        icon={s?.enabled ? <CheckCircleOutlined /> : <WarningOutlined />}
        message={s?.enabled ? t("crowdsec.active") : t("crowdsec.inactive")}
        description={s?.enabled ? `LAPI: ${s.lapi_url}` : (s?.connection_msg ?? t("crowdsec.enableBelow"))}
        action={
          s?.cache_stats && (
            <Space>
              <Statistic
                title={t("crowdsec.decisionsCached")}
                value={s.cache_stats.total_cached}
                valueStyle={{ fontSize: 14 }}
              />
              <Statistic
                title={t("crowdsec.hitRate")}
                value={s.cache_stats.hit_rate_pct}
                precision={1}
                suffix="%"
                valueStyle={{ fontSize: 14 }}
              />
            </Space>
          )
        }
      />

      <Card title={t("crowdsec.settings")}>
        <Form form={form} layout="vertical">
          <Form.Item name="enabled" valuePropName="checked" label={t("crowdsec.enableIntegration")}>
            <Switch />
          </Form.Item>
          <Row gutter={12}>
            <Col xs={24} md={12}>
              <Form.Item name="mode" label={t("crowdsec.mode")}>
                <Select
                  options={[
                    { value: "bouncer", label: t("crowdsec.modeBouncer") },
                    { value: "appsec", label: t("crowdsec.modeAppsec") },
                    { value: "both", label: t("crowdsec.modeBoth") },
                  ]}
                />
              </Form.Item>
            </Col>
            <Col xs={24} md={12}>
              <Form.Item name="fallback_action" label={t("crowdsec.fallbackAction")}>
                <Select
                  options={[
                    { value: "allow", label: t("crowdsec.fallbackAllow") },
                    { value: "block", label: t("crowdsec.fallbackBlock") },
                    { value: "log", label: t("crowdsec.fallbackLog") },
                  ]}
                />
              </Form.Item>
            </Col>
          </Row>
          <Form.Item name="lapi_url" label={t("crowdsec.lapiUrl")} rules={[{ required: true }]}>
            <Input placeholder="http://127.0.0.1:8080" />
          </Form.Item>
          <Form.Item
            name="api_key"
            label={
              <span>
                {t("crowdsec.apiKey")}
                {c?.api_key_set && <Typography.Text type="success" style={{ fontSize: 11, marginLeft: 8 }}>{t("crowdsec.keyIsSet")}</Typography.Text>}
              </span>
            }
          >
            <Input.Password placeholder={c?.api_key_set ? "(unchanged)" : "Enter bouncer API key"} />
          </Form.Item>
          <Form.Item name="update_frequency_secs" label={t("crowdsec.updateFrequency")}>
            <InputNumber min={5} max={3600} style={{ width: 160 }} />
          </Form.Item>

          {(mode === "appsec" || mode === "both") && (
            <>
              <Typography.Title level={5} style={{ marginTop: 16 }}>{t("crowdsec.appsecSettings")}</Typography.Title>
              <Form.Item name="appsec_endpoint" label={t("crowdsec.appsecEndpoint")}>
                <Input placeholder="http://127.0.0.1:7422" />
              </Form.Item>
              <Form.Item
                name="appsec_key"
                label={
                  <span>
                    {t("crowdsec.appsecKey")}
                    {c?.appsec_key_set && <Typography.Text type="success" style={{ fontSize: 11, marginLeft: 8 }}>{t("crowdsec.keyIsSet")}</Typography.Text>}
                  </span>
                }
              >
                <Input.Password placeholder={c?.appsec_key_set ? "(unchanged)" : "Enter AppSec API key"} />
              </Form.Item>
            </>
          )}

          <Space style={{ marginTop: 12 }}>
            <Button type="primary" loading={saving} onClick={onSave}>
              {saving ? t("crowdsec.saving") : t("crowdsec.saveConfig")}
            </Button>
            <Button loading={testing} onClick={onTest}>
              {testing ? t("crowdsec.testing") : t("crowdsec.testConnection")}
            </Button>
          </Space>

          {testData?.data && (
            <Alert
              style={{ marginTop: 12 }}
              type={testData.data.success ? "success" : "error"}
              message={testData.data.message}
              showIcon
            />
          )}
        </Form>
      </Card>
    </Space>
  );
};
