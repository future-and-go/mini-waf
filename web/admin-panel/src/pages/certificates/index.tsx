import {
  Card,
  Button,
  Space,
  Table,
  Tag,
  Modal,
  Form,
  Input,
  App,
  Typography,
  Popconfirm,
} from "antd";
import { CloudUploadOutlined } from "@ant-design/icons";
import { useTable, useCreate, useDelete } from "@refinedev/core";
import type { ColumnsType } from "antd/es/table";
import { useTranslation } from "react-i18next";
import { useState } from "react";
import dayjs from "dayjs";
import type { Certificate } from "../../types/api";

interface CertForm {
  host_code: string;
  domain: string;
  cert_pem: string;
  key_pem: string;
}

export const CertificatesPage: React.FC = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [form] = Form.useForm<CertForm>();
  const [open, setOpen] = useState(false);

  const { tableQuery, result } = useTable<Certificate>({
    resource: "certificates",
    pagination: { mode: "off" },
    queryOptions: { staleTime: 60_000 },
  });
  const { mutate: create, mutation: createMutation } = useCreate();
  const { mutate: del } = useDelete();
  const creating = createMutation.isPending;

  const data = Array.isArray(result?.data) ? result.data : [];

  const onSubmit = async () => {
    const values = await form.validateFields();
    create(
      {
        resource: "certificates",
        values: { ...values, auto_renew: true },
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
      { resource: "certificates", id, successNotification: false },
      {
        onSuccess: () => {
          message.success("OK");
          tableQuery.refetch();
        },
        onError: (err) => message.error(err.message),
      },
    );

  const columns: ColumnsType<Certificate> = [
    {
      title: t("certificates.domain"),
      dataIndex: "domain",
      render: (v) => <span style={{ fontFamily: "ui-monospace, monospace" }}>{v}</span>,
    },
    {
      title: t("certificates.host"),
      dataIndex: "host_code",
      render: (v) => <span style={{ fontFamily: "ui-monospace, monospace", color: "#8c8c8c" }}>{v}</span>,
    },
    { title: t("certificates.issuer"), dataIndex: "issuer", render: (v) => v ?? "—" },
    {
      title: t("certificates.expires"),
      dataIndex: "not_after",
      render: (v?: string) => (v ? dayjs(v).format("YYYY-MM-DD") : "—"),
    },
    {
      title: t("certificates.status"),
      dataIndex: "status",
      width: 100,
      render: (v: string) => <Tag color={v === "active" ? "green" : "default"}>{v}</Tag>,
    },
    {
      title: "",
      key: "ops",
      width: 80,
      render: (_v, r) => (
        <Popconfirm title={t("certificates.confirmDelete")} onConfirm={() => onDel(r.id)}>
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
          {t("certificates.title")}
        </Typography.Title>
        <Button type="primary" icon={<CloudUploadOutlined />} onClick={() => setOpen(true)}>
          {t("certificates.uploadCert")}
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
          locale={{ emptyText: t("certificates.noCerts") }}
        />
      </Card>

      <Modal
        title={t("certificates.uploadTitle")}
        open={open}
        onCancel={() => setOpen(false)}
        onOk={onSubmit}
        confirmLoading={creating}
        width={640}
        okText={t("certificates.upload")}
        cancelText={t("common.cancel")}
        destroyOnClose
      >
        <Form form={form} layout="vertical">
          <Space.Compact style={{ width: "100%" }}>
            <Form.Item name="host_code" label={t("certificates.host")} rules={[{ required: true }]} style={{ flex: 1 }}>
              <Input />
            </Form.Item>
            <Form.Item name="domain" label={t("certificates.domain")} rules={[{ required: true }]} style={{ flex: 1 }}>
              <Input placeholder="example.com" />
            </Form.Item>
          </Space.Compact>
          <Form.Item name="cert_pem" label={t("certificates.certPem")} rules={[{ required: true }]}>
            <Input.TextArea rows={5} style={{ fontFamily: "ui-monospace, monospace", fontSize: 11 }} />
          </Form.Item>
          <Form.Item name="key_pem" label={t("certificates.keyPem")} rules={[{ required: true }]}>
            <Input.TextArea rows={5} style={{ fontFamily: "ui-monospace, monospace", fontSize: 11 }} />
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  );
};
