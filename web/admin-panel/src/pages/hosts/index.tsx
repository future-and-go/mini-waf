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
  Select,
  Tooltip,
  App,
  Typography,
  Popconfirm,
  Collapse,
  Divider,
} from "antd";
import { PlusOutlined, ReloadOutlined, EditOutlined, InfoCircleOutlined } from "@ant-design/icons";
import { useTable, useCreate, useDelete, useUpdate } from "@refinedev/core";
import type { ColumnsType } from "antd/es/table";
import { useTranslation } from "react-i18next";
import { useState } from "react";
import type { Host, UpstreamAlpn, DefenseJson } from "../../types/api";

interface HostFormShape {
  host: string;
  port: number;
  ssl: boolean;
  guard_status: boolean;
  remote_host: string;
  remote_port: number;
  start_status: boolean;
  log_only_mode: boolean;
  upstream_alpn: UpstreamAlpn;
  upstream_skip_ssl_verify: boolean;
  remarks?: string;
  defense_json: DefenseJson;
}

const DEFAULT_DEFENSE: DefenseJson = {
  bot: true,
  sqli: true,
  xss: true,
  scan: true,
  rce: true,
  sensitive: true,
  dir_traversal: true,
  owasp_set: true,
  owasp_paranoia: 1,
  cc: true,
  cc_rps: 100,
  cc_burst: 200,
  cc_ban_threshold: 5,
  cc_ban_duration_secs: 600,
};

const DEFAULT_FORM: HostFormShape = {
  host: "",
  port: 80,
  ssl: false,
  guard_status: true,
  remote_host: "",
  remote_port: 8080,
  start_status: true,
  log_only_mode: false,
  upstream_alpn: "h2h1",
  upstream_skip_ssl_verify: false,
  remarks: "",
  defense_json: DEFAULT_DEFENSE,
};

export const HostsPage: React.FC = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [createForm] = Form.useForm<HostFormShape>();
  const [editForm] = Form.useForm<HostFormShape>();
  const [createOpen, setCreateOpen] = useState(false);
  const [editingHost, setEditingHost] = useState<Host | null>(null);
  const [createSsl, setCreateSsl] = useState(false);
  const [editSsl, setEditSsl] = useState(false);

  const { tableQuery, result } = useTable<Host>({
    resource: "hosts",
    pagination: { mode: "off" },
    queryOptions: { staleTime: 30_000 },
  });

  const { mutate: createHost, mutation: createMutation } = useCreate<Host>();
  const { mutate: updateHost, mutation: updateMutation } = useUpdate<Host>();
  const { mutate: deleteHost } = useDelete<Host>();
  const creating = createMutation.isPending;
  const updating = updateMutation.isPending;

  const data = Array.isArray(result?.data) ? result.data : [];

  const onSubmit = async () => {
    const values = await createForm.validateFields();
    createHost(
      { resource: "hosts", values: { ...DEFAULT_FORM, ...values }, successNotification: false },
      {
        onSuccess: () => {
          message.success(t("hosts.createdAndReloaded"));
          setCreateOpen(false);
          createForm.resetFields();
          tableQuery.refetch();
        },
        onError: (err) => message.error(err.message),
      },
    );
  };

  const onOpenEdit = (host: Host) => {
    setEditingHost(host);
    setEditSsl(host.ssl);
    editForm.setFieldsValue({
      host: host.host,
      port: host.port,
      ssl: host.ssl,
      guard_status: host.guard_status,
      remote_host: host.remote_host,
      remote_port: host.remote_port,
      start_status: host.start_status,
      log_only_mode: host.log_only_mode ?? false,
      upstream_alpn: host.upstream_alpn ?? "h2h1",
      upstream_skip_ssl_verify: host.upstream_skip_ssl_verify ?? false,
      remarks: host.remarks ?? "",
      defense_json: { ...DEFAULT_DEFENSE, ...(host.defense_json ?? {}) },
    });
  };

  const onEditSubmit = async () => {
    if (!editingHost) return;
    const values = await editForm.validateFields();
    updateHost(
      {
        resource: "hosts",
        id: editingHost.id,
        values: { ...DEFAULT_FORM, ...values },
        successNotification: false,
      },
      {
        onSuccess: () => {
          message.success(t("hosts.savedAndReloaded"));
          setEditingHost(null);
          editForm.resetFields();
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
          message.success(t("hosts.deletedAndReloaded"));
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
      title: t("common.actions"),
      key: "ops",
      width: 120,
      render: (_v, r) => (
        <Space size={0}>
          <Button type="link" size="small" icon={<EditOutlined />} onClick={() => onOpenEdit(r)}>
            {t("common.edit")}
          </Button>
          <Popconfirm title={t("hosts.confirmDelete")} onConfirm={() => onDelete(r.id)}>
            <Button type="link" danger size="small">
              {t("common.delete")}
            </Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  const alpnOptions: { value: UpstreamAlpn; label: string }[] = [
    { value: "h2h1",    label: t("hosts.alpnH2H1") },
    { value: "h1_only", label: t("hosts.alpnH1Only") },
    { value: "h2_only", label: t("hosts.alpnH2Only") },
  ];

  const formBody = (
    form: ReturnType<typeof Form.useForm<HostFormShape>>[0],
    sslOn: boolean,
    setSslOn: (v: boolean) => void,
  ) => (
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
        <Form.Item name="remote_port" label={t("hosts.upstreamPort")} rules={[{ required: true }]} style={{ flex: 1 }}>
          <InputNumber min={1} max={65535} style={{ width: "100%" }} />
        </Form.Item>
      </Space.Compact>
      <Form.Item name="remarks" label={t("hosts.remarks")}>
        <Input />
      </Form.Item>
      <Space size="large" wrap>
        <Form.Item name="ssl" label={t("hosts.ssl")} valuePropName="checked">
          <Switch onChange={setSslOn} />
        </Form.Item>
        <Form.Item name="guard_status" label={t("hosts.guard")} valuePropName="checked">
          <Switch />
        </Form.Item>
        <Form.Item name="start_status" label={t("hosts.start")} valuePropName="checked">
          <Switch />
        </Form.Item>
        <Form.Item name="log_only_mode" label={t("hosts.logOnly")} valuePropName="checked">
          <Switch />
        </Form.Item>
      </Space>
      <Form.Item
        name="upstream_alpn"
        label={
          <span>
            {t("hosts.upstreamAlpn")}&nbsp;
            <Tooltip title={t("hosts.upstreamAlpnTooltip")}>
              <InfoCircleOutlined style={{ color: "#8c8c8c" }} />
            </Tooltip>
          </span>
        }
      >
        <Select options={alpnOptions} disabled={!sslOn} style={{ width: 240 }} />
      </Form.Item>
      <Form.Item
        name="upstream_skip_ssl_verify"
        valuePropName="checked"
        label={
          <span>
            {t("hosts.skipSslVerify")}&nbsp;
            <Tooltip title={t("hosts.skipSslVerifyTooltip")}>
              <InfoCircleOutlined style={{ color: "#8c8c8c" }} />
            </Tooltip>
          </span>
        }
      >
        <Switch disabled={!sslOn} />
      </Form.Item>

      <Divider orientation="left" plain style={{ marginBottom: 0 }}>
        {t("hosts.defenseSection")}
      </Divider>

      <Collapse ghost>
        <Collapse.Panel header={t("hosts.defenseToggles")} key="toggles">
          <Space size="large" wrap>
            <Form.Item name={["defense_json", "bot"]} label="Bot" valuePropName="checked"><Switch /></Form.Item>
            <Form.Item name={["defense_json", "sqli"]} label="SQLi" valuePropName="checked"><Switch /></Form.Item>
            <Form.Item name={["defense_json", "xss"]} label="XSS" valuePropName="checked"><Switch /></Form.Item>
            <Form.Item name={["defense_json", "rce"]} label="RCE" valuePropName="checked"><Switch /></Form.Item>
            <Form.Item name={["defense_json", "scan"]} label={t("hosts.defenseScan")} valuePropName="checked"><Switch /></Form.Item>
            <Form.Item name={["defense_json", "sensitive"]} label={t("hosts.defenseSensitive")} valuePropName="checked"><Switch /></Form.Item>
            <Form.Item name={["defense_json", "dir_traversal"]} label={t("hosts.defenseDirTrav")} valuePropName="checked"><Switch /></Form.Item>
          </Space>
        </Collapse.Panel>

        <Collapse.Panel header={t("hosts.defenseOwasp")} key="owasp">
          <Space size="large" wrap>
            <Form.Item name={["defense_json", "owasp_set"]} label={t("hosts.defenseOwaspEnable")} valuePropName="checked">
              <Switch />
            </Form.Item>
            <Form.Item name={["defense_json", "owasp_paranoia"]} label={t("hosts.defenseOwaspParanoia")}>
              <Select
                style={{ width: 180 }}
                options={[
                  { value: 1, label: "PL1 — Lenient" },
                  { value: 2, label: "PL2" },
                  { value: 3, label: "PL3" },
                  { value: 4, label: "PL4 — Strict" },
                ]}
              />
            </Form.Item>
          </Space>
        </Collapse.Panel>

        <Collapse.Panel header={t("hosts.defenseCc")} key="cc">
          <Space size="large" wrap>
            <Form.Item name={["defense_json", "cc"]} label={t("hosts.defenseCcEnable")} valuePropName="checked">
              <Switch />
            </Form.Item>
            <Form.Item name={["defense_json", "cc_rps"]} label="RPS" tooltip="Token bucket refill rate (req/sec)">
              <InputNumber min={0.1} step={1} style={{ width: 130 }} />
            </Form.Item>
            <Form.Item name={["defense_json", "cc_burst"]} label="Burst" tooltip="Token bucket burst capacity">
              <InputNumber min={1} step={10} style={{ width: 130 }} />
            </Form.Item>
            <Form.Item name={["defense_json", "cc_ban_threshold"]} label={t("hosts.defenseCcBanThreshold")}>
              <InputNumber min={1} style={{ width: 130 }} />
            </Form.Item>
            <Form.Item name={["defense_json", "cc_ban_duration_secs"]} label={t("hosts.defenseCcBanDuration")}>
              <InputNumber min={1} step={60} style={{ width: 140 }} addonAfter="s" />
            </Form.Item>
          </Space>
        </Collapse.Panel>
      </Collapse>
    </Form>
  );

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
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
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

      {/* Create modal */}
      <Modal
        title={t("hosts.newHost")}
        open={createOpen}
        onCancel={() => { setCreateOpen(false); setCreateSsl(false); createForm.resetFields(); }}
        onOk={onSubmit}
        confirmLoading={creating}
        okText={t("common.create")}
        cancelText={t("common.cancel")}
        destroyOnClose
      >
        {formBody(createForm, createSsl, setCreateSsl)}
      </Modal>

      {/* Edit modal */}
      <Modal
        title={t("hosts.editHost")}
        open={!!editingHost}
        onCancel={() => { setEditingHost(null); setEditSsl(false); editForm.resetFields(); }}
        onOk={onEditSubmit}
        confirmLoading={updating}
        okText={t("common.save")}
        cancelText={t("common.cancel")}
        destroyOnClose
      >
        {formBody(editForm, editSsl, setEditSsl)}
      </Modal>
    </Space>
  );
};
