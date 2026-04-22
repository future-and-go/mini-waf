import {
  Card,
  Button,
  Space,
  Table,
  Tag,
  Modal,
  Form,
  Input,
  InputNumber,
  Switch,
  App,
  Typography,
  Popconfirm,
} from "antd";
import { PlusOutlined, ReloadOutlined } from "@ant-design/icons";
import { useTable, useCreate, useDelete } from "@refinedev/core";
import type { ColumnsType } from "antd/es/table";
import { useTranslation } from "react-i18next";
import { useState } from "react";
import type { Host } from "../../types/api";

interface HostFormShape {
  host: string;
  port: number;
  ssl: boolean;
  guard_status: boolean;
  remote_host: string;
  remote_port: number;
  start_status: boolean;
  log_only_mode: boolean;
  remarks?: string;
}

const DEFAULT_FORM: HostFormShape = {
  host: "",
  port: 80,
  ssl: false,
  guard_status: true,
  remote_host: "",
  remote_port: 8080,
  start_status: true,
  log_only_mode: false,
  remarks: "",
};

export const HostsPage: React.FC = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [form] = Form.useForm<HostFormShape>();
  const [open, setOpen] = useState(false);

  const { tableQuery, result } = useTable<Host>({
    resource: "hosts",
    pagination: { mode: "off" },
    queryOptions: { staleTime: 30_000 },
  });

  const { mutate: createHost, mutation: createMutation } = useCreate<Host>();
  const { mutate: deleteHost } = useDelete<Host>();
  const creating = createMutation.isPending;

  const data = Array.isArray(result?.data) ? result.data : [];

  const onSubmit = async () => {
    const values = await form.validateFields();
    createHost(
      { resource: "hosts", values, successNotification: false },
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

  const onDelete = (id: string) => {
    deleteHost(
      { resource: "hosts", id, successNotification: false },
      {
        onSuccess: () => {
          message.success("OK");
          tableQuery.refetch();
        },
        onError: (err) => message.error(err.message),
      },
    );
  };

  const columns: ColumnsType<Host> = [
    {
      title: t("hosts.hostname"),
      key: "host",
      render: (_v, r) => (
        <span style={{ fontFamily: "ui-monospace, monospace" }}>
          {r.host}:{r.port}
        </span>
      ),
    },
    {
      title: t("hosts.upstream"),
      key: "upstream",
      render: (_v, r) => (
        <span style={{ fontFamily: "ui-monospace, monospace", color: "#8c8c8c" }}>
          {r.remote_host}:{r.remote_port}
        </span>
      ),
    },
    {
      title: t("hosts.ssl"),
      dataIndex: "ssl",
      width: 80,
      render: (v: boolean) => <Tag color={v ? "green" : "default"}>{v ? t("hosts.ssl") : t("hosts.http")}</Tag>,
    },
    {
      title: t("hosts.guard"),
      dataIndex: "guard_status",
      width: 80,
      render: (v: boolean) => <Tag color={v ? "green" : "default"}>{v ? t("hosts.on") : t("hosts.off")}</Tag>,
    },
    {
      title: t("hosts.status"),
      dataIndex: "start_status",
      width: 100,
      render: (v: boolean) => <Tag color={v ? "green" : "default"}>{v ? t("hosts.active") : t("hosts.stopped")}</Tag>,
    },
    {
      title: "",
      key: "ops",
      width: 80,
      render: (_v, r) => (
        <Popconfirm title={t("hosts.confirmDelete")} onConfirm={() => onDelete(r.id)}>
          <Button type="link" danger size="small">
            {t("common.delete")}
          </Button>
        </Popconfirm>
      ),
    },
  ];

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <Typography.Title level={4} style={{ margin: 0 }}>
          {t("hosts.title")}
        </Typography.Title>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={() => tableQuery.refetch()}>
            {t("common.refresh")}
          </Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setOpen(true)}>
            {t("hosts.addHost")}
          </Button>
        </Space>
      </Space>

      <Card size="small">
        <Table
          rowKey="id"
          size="small"
          dataSource={data}
          columns={columns}
          loading={tableQuery.isLoading}
          pagination={false}
          locale={{ emptyText: t("hosts.noHosts") }}
        />
      </Card>

      <Modal
        title={t("hosts.newHost")}
        open={open}
        onCancel={() => setOpen(false)}
        onOk={onSubmit}
        confirmLoading={creating}
        okText={t("common.create")}
        cancelText={t("common.cancel")}
        destroyOnClose
      >
        <Form form={form} layout="vertical" initialValues={DEFAULT_FORM}>
          <Space.Compact style={{ width: "100%" }}>
            <Form.Item name="host" label={t("hosts.hostname")} rules={[{ required: true }]} style={{ flex: 2 }}>
              <Input placeholder="example.com" />
            </Form.Item>
            <Form.Item name="port" label={t("hosts.port")} rules={[{ required: true }]} style={{ flex: 1 }}>
              <InputNumber min={1} max={65535} style={{ width: "100%" }} />
            </Form.Item>
          </Space.Compact>
          <Space.Compact style={{ width: "100%" }}>
            <Form.Item name="remote_host" label={t("hosts.upstream")} rules={[{ required: true }]} style={{ flex: 2 }}>
              <Input placeholder="127.0.0.1" />
            </Form.Item>
            <Form.Item name="remote_port" label="Upstream port" rules={[{ required: true }]} style={{ flex: 1 }}>
              <InputNumber min={1} max={65535} style={{ width: "100%" }} />
            </Form.Item>
          </Space.Compact>
          <Form.Item name="remarks" label={t("hosts.remarks")}>
            <Input />
          </Form.Item>
          <Space size="large">
            <Form.Item name="ssl" label={t("hosts.ssl")} valuePropName="checked">
              <Switch />
            </Form.Item>
            <Form.Item name="guard_status" label={t("hosts.guard")} valuePropName="checked">
              <Switch />
            </Form.Item>
            <Form.Item name="start_status" label={t("hosts.start")} valuePropName="checked">
              <Switch />
            </Form.Item>
          </Space>
        </Form>
      </Modal>
    </Space>
  );
};
