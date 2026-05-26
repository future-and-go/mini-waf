import {
  Button,
  Card,
  Drawer,
  Form,
  Input,
  Modal,
  Popconfirm,
  Space,
  Switch,
  Table,
  Tag,
  Typography,
  Upload,
  App,
  Empty,
} from "antd";
import type { ColumnsType } from "antd/es/table";
import {
  ApiOutlined,
  DeleteOutlined,
  EyeOutlined,
  InboxOutlined,
  PlusOutlined,
} from "@ant-design/icons";
import { useCustom, useCustomMutation } from "@refinedev/core";
import { useTranslation } from "react-i18next";
import { useRef, useState } from "react";
import { fmtDateTime } from "../../utils/format";
import { httpClient } from "../../utils/axios";

interface Plugin {
  id: number;
  name: string;
  version: string;
  author?: string;
  description?: string;
  enabled: boolean;
  file_size?: number;
  created_at: string;
  load_error?: string;
}

interface PluginListEnvelope {
  data: Plugin[];
  total: number;
}

const fmtBytes = (b?: number) => {
  if (!b) return "—";
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1024 / 1024).toFixed(2)} MB`;
};

export const PluginsPage: React.FC = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [uploadOpen, setUploadOpen] = useState(false);
  const [detailPlugin, setDetailPlugin] = useState<Plugin | null>(null);
  const [form] = Form.useForm();
  const fileRef = useRef<File | null>(null);
  const [uploading, setUploading] = useState(false);

  const pluginsQuery = useCustom<PluginListEnvelope>({
    url: "/api/plugins",
    method: "get",
    queryOptions: { staleTime: 10_000, refetchInterval: 30_000 },
    errorNotification: false,
  });

  const { mutate: toggleMutate } = useCustomMutation();
  const { mutate: deleteMutate } = useCustomMutation();

  const plugins: Plugin[] = (() => {
    const raw = pluginsQuery.result?.data;
    if (!raw) return [];
    if (Array.isArray(raw)) return raw;
    if (Array.isArray((raw as PluginListEnvelope).data)) return (raw as PluginListEnvelope).data;
    return [];
  })();

  const handleToggle = (plugin: Plugin, checked: boolean) => {
    const endpoint = checked ? "enable" : "disable";
    toggleMutate(
      { url: `/api/plugins/${plugin.id}/${endpoint}`, method: "post", values: {} },
      {
        onSuccess: () => {
          message.success(checked ? t("plugins.enabled") : t("plugins.disabled"));
          pluginsQuery.query.refetch();
        },
        onError: () => message.error(t("plugins.toggleError")),
      }
    );
  };

  const handleDelete = (id: number) => {
    deleteMutate(
      { url: `/api/plugins/${id}`, method: "delete", values: {} },
      {
        onSuccess: () => {
          message.success(t("plugins.deleted"));
          pluginsQuery.query.refetch();
        },
        onError: () => message.error(t("plugins.deleteError")),
      }
    );
  };

  const handleUpload = async () => {
    const vals = await form.validateFields();
    if (!fileRef.current) {
      message.error(t("plugins.noFile"));
      return;
    }
    // Validate WASM magic bytes
    const buf = await fileRef.current.slice(0, 4).arrayBuffer();
    const magic = new Uint8Array(buf);
    if (magic[0] !== 0x00 || magic[1] !== 0x61 || magic[2] !== 0x73 || magic[3] !== 0x6d) {
      message.error(t("plugins.invalidWasm"));
      return;
    }
    if (fileRef.current.size > 10 * 1024 * 1024) {
      message.error(t("plugins.fileTooLarge"));
      return;
    }

    setUploading(true);
    try {
      const fd = new FormData();
      fd.append("name", vals.name);
      fd.append("version", vals.version ?? "1.0.0");
      fd.append("description", vals.description ?? "");
      fd.append("author", vals.author ?? "");
      fd.append("file", fileRef.current);

      await httpClient.post("/api/plugins", fd, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      message.success(t("plugins.uploadSuccess"));
      setUploadOpen(false);
      form.resetFields();
      fileRef.current = null;
      pluginsQuery.query.refetch();
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { error?: string } } })?.response?.data?.error ?? "Upload failed";
      message.error(msg);
    } finally {
      setUploading(false);
    }
  };

  const columns: ColumnsType<Plugin> = [
    {
      title: t("plugins.name"),
      dataIndex: "name",
      render: (v, row) => (
        <Space>
          <Typography.Text strong>{v}</Typography.Text>
          {row.load_error && <Tag color="red">Error</Tag>}
        </Space>
      ),
    },
    { title: t("plugins.version"), dataIndex: "version", width: 100 },
    { title: t("plugins.author"), dataIndex: "author", width: 140, render: v => v ?? "—" },
    {
      title: t("plugins.size"),
      dataIndex: "file_size",
      width: 100,
      render: v => fmtBytes(v),
    },
    {
      title: t("common.enabled"),
      dataIndex: "enabled",
      width: 90,
      render: (v, row) => (
        <Switch
          checked={v}
          onChange={checked => handleToggle(row, checked)}
          disabled={!!row.load_error}
        />
      ),
    },
    { title: t("common.status"), dataIndex: "created_at", width: 170, render: v => fmtDateTime(v) },
    {
      title: t("common.actions"),
      width: 120,
      render: (_, row) => (
        <Space>
          <Button size="small" icon={<EyeOutlined />} onClick={() => setDetailPlugin(row)} />
          <Popconfirm
            title={t("plugins.confirmDelete")}
            onConfirm={() => handleDelete(row.id)}
            okButtonProps={{ danger: true }}
          >
            <Button size="small" danger icon={<DeleteOutlined />} />
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <>
      <Card
        title={
          <Space>
            <ApiOutlined />
            <span>{t("plugins.title")}</span>
          </Space>
        }
        extra={
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setUploadOpen(true)}>
            {t("plugins.upload")}
          </Button>
        }
        loading={pluginsQuery.query.isLoading}
      >
        <Typography.Paragraph type="secondary">{t("plugins.subtitle")}</Typography.Paragraph>
        {plugins.length === 0 && !pluginsQuery.query.isLoading ? (
          <Empty
            description={
              <Space direction="vertical" align="center">
                <Typography.Text type="secondary">{t("plugins.noPlugins")}</Typography.Text>
                <Typography.Link href="/docs/plugins-getting-started" target="_blank">
                  {t("plugins.gettingStarted")}
                </Typography.Link>
              </Space>
            }
          />
        ) : (
          <Table
            dataSource={plugins}
            columns={columns}
            rowKey="id"
            size="small"
            pagination={{ pageSize: 20 }}
          />
        )}
      </Card>

      {/* Upload modal */}
      <Modal
        title={t("plugins.uploadTitle")}
        open={uploadOpen}
        onOk={handleUpload}
        onCancel={() => { setUploadOpen(false); form.resetFields(); fileRef.current = null; }}
        confirmLoading={uploading}
        okText={t("plugins.upload")}
      >
        <Form form={form} layout="vertical">
          <Form.Item name="name" label={t("common.name")} rules={[{ required: true }]}>
            <Input placeholder="my-plugin" />
          </Form.Item>
          <Form.Item name="version" label={t("plugins.version")}>
            <Input placeholder="1.0.0" />
          </Form.Item>
          <Form.Item name="author" label={t("plugins.author")}>
            <Input />
          </Form.Item>
          <Form.Item name="description" label={t("common.description")}>
            <Input.TextArea rows={2} />
          </Form.Item>
          <Form.Item label={t("plugins.wasmFile")} required>
            <Upload.Dragger
              accept=".wasm"
              maxCount={1}
              beforeUpload={file => {
                fileRef.current = file;
                return false;
              }}
            >
              <p className="ant-upload-drag-icon"><InboxOutlined /></p>
              <p>{t("plugins.dropWasm")}</p>
              <p className="ant-upload-hint">{t("plugins.wasmHint")}</p>
            </Upload.Dragger>
          </Form.Item>
        </Form>
      </Modal>

      {/* Detail drawer */}
      <Drawer
        title={detailPlugin?.name}
        open={!!detailPlugin}
        onClose={() => setDetailPlugin(null)}
        width={480}
      >
        {detailPlugin && (
          <Space direction="vertical" style={{ width: "100%" }}>
            <Card size="small">
              <Space direction="vertical">
                <div><Typography.Text strong>{t("plugins.version")}: </Typography.Text>{detailPlugin.version}</div>
                <div><Typography.Text strong>{t("plugins.author")}: </Typography.Text>{detailPlugin.author ?? "—"}</div>
                <div><Typography.Text strong>{t("plugins.size")}: </Typography.Text>{fmtBytes(detailPlugin.file_size)}</div>
                <div><Typography.Text strong>{t("common.status")}: </Typography.Text>
                  <Tag color={detailPlugin.enabled ? "green" : "default"}>
                    {detailPlugin.enabled ? t("common.enabled") : t("common.disabled")}
                  </Tag>
                </div>
                <div><Typography.Text strong>{t("common.status")}: </Typography.Text>{fmtDateTime(detailPlugin.created_at)}</div>
              </Space>
            </Card>
            {detailPlugin.description && (
              <Card size="small" title={t("common.description")}>
                <Typography.Text>{detailPlugin.description}</Typography.Text>
              </Card>
            )}
            {detailPlugin.load_error && (
              <Card size="small" title="Load Error">
                <Typography.Text type="danger" code>{detailPlugin.load_error}</Typography.Text>
              </Card>
            )}
          </Space>
        )}
      </Drawer>
    </>
  );
};
