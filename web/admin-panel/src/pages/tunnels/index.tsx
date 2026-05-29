import {
  Button,
  Card,
  Drawer,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Select,
  Space,
  Table,
  Tag,
  Typography,
  App,
  Statistic,
  Row,
  Col,
} from "antd";
import type { ColumnsType } from "antd/es/table";
import {
  DeleteOutlined,
  PlusOutlined,
  ShareAltOutlined,
  EyeOutlined,
} from "@ant-design/icons";
import { useCustom, useCustomMutation } from "@refinedev/core";
import { useTranslation } from "react-i18next";
import { useEffect, useRef, useState } from "react";
import { fmtDateTime } from "../../utils/format";

interface Tunnel {
  id: number;
  name: string;
  local_port: number;
  target_host: string;
  target_port: number;
  protocol: "tcp" | "udp" | "ws";
  status?: string;
  created_at: string;
}

interface TunnelStats {
  bytes_in: number;
  bytes_out: number;
  active_connections: number;
}

interface TunnelListEnvelope {
  data: Tunnel[];
  total: number;
}

const fmtBytes = (b?: number) => {
  if (!b) return "0 B";
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1024 / 1024).toFixed(2)} MB`;
};

export const TunnelsPage: React.FC = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [createOpen, setCreateOpen] = useState(false);
  const [detailTunnel, setDetailTunnel] = useState<Tunnel | null>(null);
  const [tunnelStats, setTunnelStats] = useState<TunnelStats | null>(null);
  const [form] = Form.useForm();
  const wsRef = useRef<WebSocket | null>(null);

  const tunnelsQuery = useCustom<TunnelListEnvelope>({
    url: "/api/tunnels",
    method: "get",
    queryOptions: { staleTime: 10_000, refetchInterval: 15_000 },
    errorNotification: false,
  });

  const { mutate: createMutate, mutation: createMutation } = useCustomMutation();
  const { mutate: deleteMutate } = useCustomMutation();

  const tunnels: Tunnel[] = (() => {
    const raw = tunnelsQuery.result?.data;
    if (!raw) return [];
    if (Array.isArray(raw)) return raw;
    if (Array.isArray((raw as TunnelListEnvelope).data)) return (raw as TunnelListEnvelope).data;
    return [];
  })();

  // Connect WS stats when drawer opens
  useEffect(() => {
    if (!detailTunnel) {
      wsRef.current?.close();
      wsRef.current = null;
      setTunnelStats(null);
      return;
    }
    if (detailTunnel.status !== "active") return;

    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const token = localStorage.getItem("access_token") ?? "";
    const url = `${proto}//${window.location.host}/ws/tunnel?tunnel_id=${detailTunnel.id}&token=${token}`;
    const ws = new WebSocket(url);
    wsRef.current = ws;
    ws.onmessage = e => {
      try { setTunnelStats(JSON.parse(e.data)); } catch {}
    };
    return () => ws.close();
  }, [detailTunnel]);

  const handleCreate = async () => {
    const vals = await form.validateFields();
    if (vals.local_port < 1024) {
      // Popconfirm handled separately via low-port warning
    }
    createMutate(
      { url: "/api/tunnels", method: "post", values: vals },
      {
        onSuccess: () => {
          message.success(t("tunnels.created"));
          setCreateOpen(false);
          form.resetFields();
          tunnelsQuery.query.refetch();
        },
        onError: () => message.error(t("tunnels.createError")),
      }
    );
  };

  const handleDelete = (id: number) => {
    deleteMutate(
      { url: `/api/tunnels/${id}`, method: "delete", values: {} },
      {
        onSuccess: () => {
          message.success(t("tunnels.deleted"));
          tunnelsQuery.query.refetch();
        },
        onError: () => message.error(t("tunnels.deleteError")),
      }
    );
  };

  const columns: ColumnsType<Tunnel> = [
    { title: t("tunnels.name"), dataIndex: "name", render: v => <Typography.Text strong>{v}</Typography.Text> },
    { title: t("tunnels.localPort"), dataIndex: "local_port", width: 110 },
    {
      title: t("tunnels.target"),
      render: (_, row) => `${row.target_host}:${row.target_port}`,
      width: 200,
    },
    {
      title: t("tunnels.protocol"),
      dataIndex: "protocol",
      width: 90,
      render: (v?: string) => <Tag color={v === "tcp" ? "blue" : v === "udp" ? "green" : "purple"}>{(v ?? "—").toUpperCase()}</Tag>,
    },
    {
      title: t("common.status"),
      dataIndex: "status",
      width: 100,
      render: v => <Tag color={v === "active" ? "green" : "default"}>{v ?? "—"}</Tag>,
    },
    { title: t("common.status"), dataIndex: "created_at", width: 170, render: v => fmtDateTime(v) },
    {
      title: t("common.actions"),
      width: 120,
      render: (_, row) => (
        <Space>
          <Button size="small" icon={<EyeOutlined />} onClick={() => setDetailTunnel(row)} />
          <Popconfirm
            title={t("tunnels.confirmDelete")}
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
            <ShareAltOutlined />
            <span>{t("tunnels.title")}</span>
          </Space>
        }
        extra={
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
            {t("tunnels.createTunnel")}
          </Button>
        }
        loading={tunnelsQuery.query.isLoading}
      >
        <Typography.Paragraph type="secondary">{t("tunnels.subtitle")}</Typography.Paragraph>
        <Table
          dataSource={tunnels}
          columns={columns}
          rowKey="id"
          size="small"
          pagination={{ pageSize: 20 }}
        />
      </Card>

      {/* Create modal */}
      <Modal
        title={t("tunnels.createTunnel")}
        open={createOpen}
        onOk={handleCreate}
        onCancel={() => { setCreateOpen(false); form.resetFields(); }}
        confirmLoading={createMutation.isPending}
        okText={t("common.create")}
      >
        <Form form={form} layout="vertical">
          <Form.Item name="name" label={t("common.name")} rules={[{ required: true }]}>
            <Input placeholder="my-tunnel" />
          </Form.Item>
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item name="local_port" label={t("tunnels.localPort")} rules={[{ required: true }]}>
                <InputNumber min={1} max={65535} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="protocol" label={t("tunnels.protocol")} rules={[{ required: true }]} initialValue="tcp">
                <Select options={[
                  { value: "tcp", label: "TCP" },
                  { value: "udp", label: "UDP" },
                  { value: "ws", label: "WebSocket" },
                ]} />
              </Form.Item>
            </Col>
          </Row>
          <Row gutter={16}>
            <Col span={16}>
              <Form.Item name="target_host" label={t("tunnels.targetHost")} rules={[{ required: true }]}>
                <Input placeholder="localhost" />
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item name="target_port" label={t("tunnels.targetPort")} rules={[{ required: true }]}>
                <InputNumber min={1} max={65535} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
          </Row>
        </Form>
      </Modal>

      {/* Detail drawer */}
      <Drawer
        title={
          <Space>
            <ShareAltOutlined />
            {detailTunnel?.name}
          </Space>
        }
        open={!!detailTunnel}
        onClose={() => setDetailTunnel(null)}
        width={480}
      >
        {detailTunnel && (
          <Space direction="vertical" style={{ width: "100%" }}>
            <Card size="small" title={t("tunnels.info")}>
              <Space direction="vertical">
                <div><Typography.Text strong>{t("tunnels.localPort")}: </Typography.Text>{detailTunnel.local_port}</div>
                <div><Typography.Text strong>{t("tunnels.target")}: </Typography.Text>{detailTunnel.target_host}:{detailTunnel.target_port}</div>
                <div><Typography.Text strong>{t("tunnels.protocol")}: </Typography.Text>
                  <Tag>{(detailTunnel.protocol ?? "—").toUpperCase()}</Tag>
                </div>
              </Space>
            </Card>
            {detailTunnel.status === "active" && tunnelStats && (
              <Card size="small" title={t("tunnels.liveStats")}>
                <Row gutter={16}>
                  <Col span={8}>
                    <Statistic title={t("tunnels.activeConns")} value={tunnelStats.active_connections} />
                  </Col>
                  <Col span={8}>
                    <Statistic title={t("tunnels.bytesIn")} value={fmtBytes(tunnelStats.bytes_in)} />
                  </Col>
                  <Col span={8}>
                    <Statistic title={t("tunnels.bytesOut")} value={fmtBytes(tunnelStats.bytes_out)} />
                  </Col>
                </Row>
              </Card>
            )}
          </Space>
        )}
      </Drawer>
    </>
  );
};
