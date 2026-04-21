import {
  Card,
  Row,
  Col,
  Typography,
  Space,
  Button,
  Input,
  InputNumber,
  Switch,
  Form,
  Tag,
  List,
  Popconfirm,
  App,
} from "antd";
import { CloseOutlined } from "@ant-design/icons";
import { useList, useCreate, useDelete, useCustomMutation } from "@refinedev/core";
import { useTranslation } from "react-i18next";
import { useState } from "react";
import type { LbBackend } from "../../types/api";

interface BackendForm {
  host_code: string;
  backend_host: string;
  backend_port: number;
}

interface HotlinkForm {
  host_code: string;
  enabled: boolean;
  allow_empty_referer: boolean;
  redirect_url?: string;
}

export const CcProtectionPage: React.FC = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();

  const backends = useList<LbBackend>({
    resource: "lb-backends",
    pagination: { mode: "off" },
    queryOptions: { staleTime: 30_000 },
  });

  const { mutate: createBackend } = useCreate();
  const { mutate: deleteBackend } = useDelete();
  const { mutate: upsertHotlink, mutation: hotlinkMutation } = useCustomMutation();
  const savingHotlink = hotlinkMutation.isPending;

  const [backendForm] = Form.useForm<BackendForm>();
  const [hotlinkForm] = Form.useForm<HotlinkForm>();
  const [showBackend, setShowBackend] = useState(false);

  const onAddBackend = async () => {
    const values = await backendForm.validateFields();
    createBackend(
      { resource: "lb-backends", values, successNotification: false },
      {
        onSuccess: () => {
          message.success("OK");
          backendForm.resetFields();
          backends.query.refetch();
        },
        onError: (err) => message.error(err.message),
      },
    );
  };

  const onDelBackend = (id: string) =>
    deleteBackend(
      { resource: "lb-backends", id, successNotification: false },
      {
        onSuccess: () => backends.query.refetch(),
        onError: (err) => message.error(err.message),
      },
    );

  const onSaveHotlink = async () => {
    const values = await hotlinkForm.validateFields();
    upsertHotlink(
      { url: "/api/hotlink-config", method: "post", values },
      {
        onSuccess: () => message.success(t("ccProtection.hotlinkSaved")),
        onError: (err) => message.error(err.message),
      },
    );
  };

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Typography.Title level={4} style={{ margin: 0 }}>
        {t("ccProtection.title")}
      </Typography.Title>

      <Row gutter={[12, 12]}>
        <Col xs={24} lg={12}>
          <Card
            size="small"
            title={t("ccProtection.backends")}
            extra={
              <Button type="link" size="small" onClick={() => setShowBackend((s) => !s)}>
                {t("ccProtection.addBackend")}
              </Button>
            }
            loading={backends.query.isLoading}
          >
            {showBackend && (
              <Form
                form={backendForm}
                layout="inline"
                style={{ marginBottom: 12, gap: 8 }}
                initialValues={{ backend_port: 8080 }}
              >
                <Form.Item name="backend_host" rules={[{ required: true }]}>
                  <Input placeholder={t("ccProtection.backendHost")} style={{ width: 160 }} />
                </Form.Item>
                <Form.Item name="backend_port" rules={[{ required: true }]}>
                  <InputNumber min={1} max={65535} placeholder={t("ccProtection.backendPort")} style={{ width: 100 }} />
                </Form.Item>
                <Form.Item name="host_code">
                  <Input placeholder={t("ccProtection.hostCode")} style={{ width: 130 }} />
                </Form.Item>
                <Button type="primary" size="small" onClick={onAddBackend}>
                  {t("common.add")}
                </Button>
              </Form>
            )}

            <List
              size="small"
              dataSource={Array.isArray(backends.result?.data) ? backends.result.data : []}
              locale={{ emptyText: t("ccProtection.noBackends") }}
              renderItem={(b) => (
                <List.Item
                  actions={[
                    <Tag key="h" color={b.is_healthy ? "green" : "red"}>
                      {b.is_healthy ? t("ccProtection.healthy") : t("ccProtection.unhealthy")}
                    </Tag>,
                    <Popconfirm key="d" title={t("common.confirm")} onConfirm={() => onDelBackend(b.id)}>
                      <Button size="small" type="text" icon={<CloseOutlined />} danger />
                    </Popconfirm>,
                  ]}
                >
                  <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>
                    {b.backend_host}:{b.backend_port}
                  </span>
                </List.Item>
              )}
            />
          </Card>
        </Col>

        <Col xs={24} lg={12}>
          <Card size="small" title={t("ccProtection.hotlink")}>
            <Form
              form={hotlinkForm}
              layout="vertical"
              initialValues={{ enabled: true, allow_empty_referer: true }}
            >
              <Form.Item name="host_code" label={t("ccProtection.hostCode")}>
                <Input placeholder="*" />
              </Form.Item>
              <Space size="large" style={{ marginBottom: 12 }}>
                <Form.Item name="enabled" valuePropName="checked" noStyle>
                  <Switch />
                </Form.Item>
                <span>{t("ccProtection.enabled")}</span>
                <Form.Item name="allow_empty_referer" valuePropName="checked" noStyle>
                  <Switch />
                </Form.Item>
                <span>{t("ccProtection.allowEmptyReferer")}</span>
              </Space>
              <Form.Item name="redirect_url" label={t("ccProtection.redirectUrl")}>
                <Input />
              </Form.Item>
              <Button type="primary" loading={savingHotlink} onClick={onSaveHotlink}>
                {t("common.save")}
              </Button>
            </Form>
          </Card>
        </Col>
      </Row>
    </Space>
  );
};
