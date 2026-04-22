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
  App,
  Typography,
  Popconfirm,
} from "antd";
import { PlusOutlined } from "@ant-design/icons";
import { useTable, useCreate, useDelete, useCustomMutation } from "@refinedev/core";
import type { ColumnsType } from "antd/es/table";
import { useTranslation } from "react-i18next";
import { useState } from "react";
import { fmtDateTime } from "../../utils/format";
import type { NotificationConfig } from "../../types/api";

interface NotifForm {
  name: string;
  channel_type: string;
  event_type: string;
  host_code?: string;
  config_json?: string;
}

const placeholderFor = (channel: string): string => {
  if (channel === "webhook") return '{"url": "https://hooks.example.com/..."}';
  if (channel === "telegram") return '{"bot_token": "...", "chat_id": "..."}';
  return '{"smtp_host": "smtp.gmail.com", "smtp_port": 587, "from": "waf@example.com", "to": ["admin@example.com"]}';
};

export const NotificationsPage: React.FC = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [form] = Form.useForm<NotifForm>();
  const [open, setOpen] = useState(false);
  const [channel, setChannel] = useState("webhook");

  const { tableQuery, result } = useTable<NotificationConfig>({
    resource: "notifications",
    pagination: { mode: "off" },
    queryOptions: { staleTime: 30_000 },
  });
  const { mutate: create, mutation: createMutation } = useCreate();
  const { mutate: del } = useDelete();
  const { mutate: testNotif } = useCustomMutation();
  const creating = createMutation.isPending;

  const data = Array.isArray(result?.data) ? result.data : [];

  const onSubmit = async () => {
    const v = await form.validateFields();
    let cfg: unknown = {};
    try {
      cfg = JSON.parse(v.config_json ?? "{}");
    } catch {
      message.error("Invalid JSON config");
      return;
    }
    create(
      {
        resource: "notifications",
        values: {
          name: v.name,
          channel_type: v.channel_type,
          event_type: v.event_type,
          host_code: v.host_code,
          config_json: cfg,
        },
        successNotification: false,
      },
      {
        onSuccess: () => {
          message.success("OK");
          setOpen(false);
          form.resetFields();
          tableQuery.refetch();
        },
        onError: (err) => message.error(err.message),
      },
    );
  };

  const onDel = (id: string) =>
    del(
      { resource: "notifications", id, successNotification: false },
      {
        onSuccess: () => {
          message.success("OK");
          tableQuery.refetch();
        },
        onError: (err) => message.error(err.message),
      },
    );

  const onTest = (id: string) =>
    testNotif(
      { url: `/api/notifications/${id}/test`, method: "post", values: {} },
      {
        onSuccess: () => message.success(t("notifications.testSent")),
        onError: (err) => message.error(t("notifications.failed") + err.message),
      },
    );

  const columns: ColumnsType<NotificationConfig> = [
    { title: t("notifications.name"), dataIndex: "name" },
    { title: t("notifications.event"), dataIndex: "event_type" },
    { title: t("notifications.channel"), dataIndex: "channel_type", render: (v) => <Tag color="blue">{v}</Tag> },
    {
      title: t("notifications.lastTriggered"),
      dataIndex: "last_triggered",
      render: (v?: string) => (v ? fmtDateTime(v) : t("common.never")),
    },
    {
      title: "",
      key: "ops",
      width: 140,
      render: (_v, r) => (
        <Space>
          <Button size="small" type="link" onClick={() => onTest(r.id)}>
            {t("common.test")}
          </Button>
          <Popconfirm title={t("notifications.confirmDelete")} onConfirm={() => onDel(r.id)}>
            <Button size="small" type="link" danger>
              {t("common.delete")}
            </Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <Typography.Title level={4} style={{ margin: 0 }}>
          {t("notifications.title")}
        </Typography.Title>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setOpen(true)}>
          {t("notifications.addConfig")}
        </Button>
      </Space>

      <Card size="small">
        <Table
          rowKey="id"
          size="small"
          dataSource={data}
          columns={columns}
          loading={tableQuery.isLoading}
          pagination={false}
          locale={{ emptyText: t("notifications.noConfigs") }}
        />
      </Card>

      <Modal
        title={t("notifications.newConfig")}
        open={open}
        onCancel={() => setOpen(false)}
        onOk={onSubmit}
        confirmLoading={creating}
        okText={t("common.create")}
        cancelText={t("common.cancel")}
        width={600}
        destroyOnClose
      >
        <Form
          form={form}
          layout="vertical"
          initialValues={{ channel_type: "webhook", event_type: "attack_detected", config_json: "{}" }}
          onValuesChange={(c) => c.channel_type && setChannel(c.channel_type)}
        >
          <Space.Compact style={{ width: "100%" }}>
            <Form.Item name="name" label={t("notifications.name")} rules={[{ required: true }]} style={{ flex: 1 }}>
              <Input />
            </Form.Item>
            <Form.Item name="channel_type" label={t("notifications.channel")} style={{ flex: 1 }}>
              <Select
                options={[
                  { value: "webhook", label: t("notifications.webhook") },
                  { value: "telegram", label: t("notifications.telegram") },
                  { value: "email", label: t("notifications.email") },
                ]}
              />
            </Form.Item>
          </Space.Compact>
          <Space.Compact style={{ width: "100%" }}>
            <Form.Item name="event_type" label={t("notifications.event")} style={{ flex: 1 }}>
              <Select
                options={[
                  { value: "attack_detected", label: t("notifications.attackDetected") },
                  { value: "cert_expiry", label: t("notifications.certExpiry") },
                  { value: "high_traffic", label: t("notifications.highTraffic") },
                  { value: "backend_down", label: t("notifications.backendDown") },
                ]}
              />
            </Form.Item>
            <Form.Item name="host_code" label={t("ccProtection.hostCode")} style={{ flex: 1 }}>
              <Input />
            </Form.Item>
          </Space.Compact>
          <Form.Item name="config_json" label={t("notifications.channelConfig")}>
            <Input.TextArea rows={5} placeholder={placeholderFor(channel)} style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }} />
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  );
};
