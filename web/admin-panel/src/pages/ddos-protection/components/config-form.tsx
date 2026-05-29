import { Card, Form, InputNumber, Switch, Row, Col, Select, Input, Space } from "antd";
import type { FormInstance } from "antd";
import type { TFunction } from "i18next";
import { DEFAULT_CONFIG, type DdosConfig } from "../types";

interface ConfigFormProps {
  form: FormInstance<DdosConfig>;
  currentBackend: string;
  disabled?: boolean;
  t: TFunction;
}

export const ConfigForm: React.FC<ConfigFormProps> = ({ form, currentBackend, disabled, t }) => (
  <Form form={form} layout="vertical" initialValues={DEFAULT_CONFIG} size="small" disabled={disabled}>
    <Form.Item name="enabled" valuePropName="checked" label={t("ddos.enabled")}>
      <Switch />
    </Form.Item>

    <Row gutter={24}>
      <Col xs={24} md={12}>
        <Card size="small" title={t("ddos.perIp")} style={{ marginBottom: 12 }}>
          <Row gutter={12}>
            <Col span={12}>
              <Form.Item
                name={["per_ip", "threshold_rps"]}
                label={t("ddos.thresholdRps")}
                rules={[{ required: true }]}
              >
                <InputNumber min={1} addonAfter="rps" style={{ width: "100%" }} />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item
                name={["per_ip", "window_secs"]}
                label={t("ddos.windowSecs")}
                rules={[{ required: true }]}
              >
                <InputNumber min={1} addonAfter="s" style={{ width: "100%" }} />
              </Form.Item>
            </Col>
          </Row>
        </Card>
      </Col>

      <Col xs={24} md={12}>
        <Card size="small" title={t("ddos.perFingerprint")} style={{ marginBottom: 12 }}>
          <Row gutter={12}>
            <Col span={12}>
              <Form.Item
                name={["per_fingerprint", "threshold_rps"]}
                label={t("ddos.thresholdRps")}
                rules={[{ required: true }]}
              >
                <InputNumber min={1} addonAfter="rps" style={{ width: "100%" }} />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item
                name={["per_fingerprint", "window_secs"]}
                label={t("ddos.windowSecs")}
                rules={[{ required: true }]}
              >
                <InputNumber min={1} addonAfter="s" style={{ width: "100%" }} />
              </Form.Item>
            </Col>
          </Row>
        </Card>
      </Col>
    </Row>

    <Card size="small" title={t("ddos.banEscalation")} style={{ marginBottom: 12 }}>
      <Space wrap>
        {[0, 1, 2].map((i) => (
          <Form.Item
            key={i}
            name={["ban_durations_secs", i]}
            label={t(`ddos.banLevel${i + 1}`)}
            rules={[{ required: true }]}
            style={{ marginBottom: 0 }}
          >
            <InputNumber min={1} addonAfter="s" style={{ width: 130 }} />
          </Form.Item>
        ))}
      </Space>
    </Card>

    <Card size="small" title={t("ddos.storeBackend")} style={{ marginBottom: 0 }}>
      <Row gutter={12}>
        <Col xs={24} sm={8}>
          <Form.Item
            name={["store", "backend"]}
            label={t("ddos.backend")}
            rules={[{ required: true }]}
          >
            <Select
              options={[
                { value: "memory", label: t("ddos.backendMemory") },
                { value: "redis", label: t("ddos.backendRedis") },
              ]}
            />
          </Form.Item>
        </Col>
        {currentBackend === "redis" && (
          <Col xs={24} sm={16}>
            <Form.Item
              name={["store", "redis_url"]}
              label={t("ddos.redisUrl")}
              rules={[{ required: true, message: t("ddos.redisUrlRequired") }]}
            >
              <Input
                placeholder="redis://127.0.0.1:6379"
                style={{ fontFamily: "ui-monospace, monospace" }}
              />
            </Form.Item>
          </Col>
        )}
      </Row>
    </Card>
  </Form>
);
