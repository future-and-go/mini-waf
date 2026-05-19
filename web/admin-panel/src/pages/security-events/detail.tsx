import { useState } from "react";
import {
  Row, Col, Card, Button, Space, Typography, Tag, Descriptions,
  Table, Collapse, Skeleton, Result, Modal, message,
} from "antd";
import {
  ArrowLeftOutlined,
  ClockCircleOutlined,
  GlobalOutlined,
  CopyOutlined,
  StopOutlined,
  LinkOutlined,
} from "@ant-design/icons";
import { useOne, useCustom, useCreate, useGetIdentity } from "@refinedev/core";
import { useTranslation } from "react-i18next";
import { useNavigate, useParams } from "react-router-dom";
import type { ColumnsType } from "antd/es/table";

import type { SecurityEvent } from "../../types/api";
import { deriveCategory } from "../../types/api";
import { actionColors } from "../../components/category-bars";
import { fmtDateTime } from "../../utils/format";

interface IdentityShape {
  name?: string;
  role?: string;
}

// ── Mini table for related events ─────────────────────────────────────────────

interface RelatedTableProps {
  events: SecurityEvent[];
  loading: boolean;
  showIp?: boolean;
}

const relatedCols = (showIp: boolean): ColumnsType<SecurityEvent> => [
  {
    title: "Time",
    dataIndex: "created_at",
    width: 150,
    render: (v: string) => (
      <span style={{ color: "#8c8c8c", fontSize: 11 }}>{fmtDateTime(v)}</span>
    ),
  },
  ...(showIp
    ? [{
        title: "IP",
        dataIndex: "client_ip",
        width: 130,
        render: (v: string) => (
          <Typography.Text code style={{ fontSize: 11 }}>{v}</Typography.Text>
        ),
      } as ColumnsType<SecurityEvent>[number]]
    : []),
  {
    title: "Path",
    dataIndex: "path",
    ellipsis: true,
    render: (v: string) => (
      <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 11 }} title={v}>{v}</span>
    ),
  },
  {
    title: "Action",
    dataIndex: "action",
    width: 80,
    render: (v: string) => (
      <Tag color={actionColors[v] ?? "default"} style={{ color: "#fff", fontSize: 10 }}>
        {v}
      </Tag>
    ),
  },
];

const RelatedTable: React.FC<RelatedTableProps> = ({ events, loading, showIp }) => (
  <Table
    rowKey="id"
    size="small"
    dataSource={events}
    columns={relatedCols(!!showIp)}
    loading={loading}
    pagination={false}
    scroll={{ x: 400 }}
    locale={{ emptyText: "No related events" }}
  />
);

// ── Main page ─────────────────────────────────────────────────────────────────

export const SecurityEventDetailPage: React.FC = () => {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { id } = useParams<{ id: string }>();
  const { data: identity } = useGetIdentity<IdentityShape>();
  const [blockModalOpen, setBlockModalOpen] = useState(false);
  const [messageApi, contextHolder] = message.useMessage();

  const isAdmin = identity?.role === "admin";

  // Backend has GET /api/security-events/{id} — use useOne directly.
  const { query } = useOne<SecurityEvent>({
    resource: "security-events",
    id: id ?? "",
    queryOptions: { enabled: !!id },
  });

  const event = query.data?.data;
  const isLoading = query.isLoading;
  const isError = query.isError;

  // Related: same IP
  const sameIpQuery = useCustom<{ data: SecurityEvent[] }>({
    url: "/api/security-events",
    method: "get",
    config: {
      query: {
        client_ip: event?.client_ip,
        page_size: 10,
        page: 1,
      },
    },
    queryOptions: {
      enabled: !!event?.client_ip,
      staleTime: 30_000,
      queryKey: ["related-ip", event?.client_ip],
    },
  });

  // Related: same rule (filter by rule_name per backend SecurityEventQuery)
  const sameRuleQuery = useCustom<{ data: SecurityEvent[] }>({
    url: "/api/security-events",
    method: "get",
    config: {
      query: {
        rule_name: event?.rule_name,
        page_size: 10,
        page: 1,
      },
    },
    queryOptions: {
      enabled: !!event?.rule_name,
      staleTime: 30_000,
      queryKey: ["related-rule", event?.rule_name],
    },
  });

  const { mutate: createBlockIp } = useCreate();

  const sameIpEvents = (() => {
    const raw = sameIpQuery.result?.data;
    return Array.isArray(raw)
      ? (raw as SecurityEvent[])
      : Array.isArray((raw as unknown as { data: SecurityEvent[] })?.data)
      ? (raw as unknown as { data: SecurityEvent[] }).data
      : [];
  })();

  const sameRuleEvents = (() => {
    const raw = sameRuleQuery.result?.data;
    return Array.isArray(raw)
      ? (raw as SecurityEvent[])
      : Array.isArray((raw as unknown as { data: SecurityEvent[] })?.data)
      ? (raw as unknown as { data: SecurityEvent[] }).data
      : [];
  })();

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text).then(() => {
      messageApi.success(`${label} ${t("eventDetail.copied")}`);
    }).catch(() => {
      messageApi.error("Copy failed");
    });
  };

  const handleAddToBlocklist = () => {
    if (!event) return;
    createBlockIp(
      {
        resource: "block-ips",
        values: {
          ip_cidr: `${event.client_ip}/32`,
          host_code: event.host_code,
          remarks: `From event ${event.id}`,
        },
      },
      {
        onSuccess: () => {
          messageApi.success(t("eventDetail.addedToBlocklist"));
          setBlockModalOpen(false);
        },
        onError: (err) => {
          messageApi.error(err.message ?? "Failed to add to blocklist");
        },
      },
    );
  };

  if (isLoading) {
    return (
      <Card>
        <Skeleton active paragraph={{ rows: 10 }} />
      </Card>
    );
  }

  if (isError || !event) {
    return (
      <Result
        status="404"
        title={t("eventDetail.notFound")}
        extra={
          <Button icon={<ArrowLeftOutlined />} onClick={() => navigate(-1)}>
            {t("eventDetail.back")}
          </Button>
        }
      />
    );
  }

  const geo = event.geo_info;
  const category = deriveCategory(event.rule_id);

  return (
    <>
      {contextHolder}
      <Space direction="vertical" size="middle" style={{ width: "100%" }}>
        {/* Header */}
        <Row justify="space-between" align="middle">
          <Col>
            <Space>
              <Button
                icon={<ArrowLeftOutlined />}
                onClick={() => navigate(-1)}
                type="text"
              >
                {t("eventDetail.back")}
              </Button>
              <Typography.Title level={4} style={{ margin: 0 }}>
                {t("eventDetail.title")}
              </Typography.Title>
              <Typography.Text code style={{ fontSize: 12 }}>{event.id}</Typography.Text>
            </Space>
            <div style={{ marginTop: 4 }}>
              <Space>
                <Tag color={actionColors[event.action] ?? "default"} style={{ color: "#fff" }}>
                  {event.action}
                </Tag>
                <Tag color="#722ed1" style={{ color: "#fff" }}>{category}</Tag>
              </Space>
            </div>
          </Col>
          <Col>
            <Space>
              <Button
                icon={<LinkOutlined />}
                onClick={() => navigate(`/security-events?client_ip=${event.client_ip}`)}
              >
                {t("eventDetail.viewAllFromIp")}
              </Button>
              <Button
                icon={<LinkOutlined />}
                onClick={() => navigate(`/security-events?rule_name=${encodeURIComponent(event.rule_name)}`)}
              >
                {t("eventDetail.viewAllForRule")}
              </Button>
              {isAdmin && event.action === "block" && (
                <Button
                  danger
                  icon={<StopOutlined />}
                  onClick={() => setBlockModalOpen(true)}
                >
                  {t("eventDetail.addToBlocklist")}
                </Button>
              )}
            </Space>
          </Col>
        </Row>

        {/* Overview */}
        <Card size="small" title={t("eventDetail.overview")}>
          <Descriptions
            column={{ xs: 1, sm: 2 }}
            size="middle"
            bordered
          >
            <Descriptions.Item label={<Space><ClockCircleOutlined /> {t("security.time")}</Space>}>
              {fmtDateTime(event.created_at)}
            </Descriptions.Item>
            <Descriptions.Item label={t("security.hostCode")}>
              <Tag>{event.host_code}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label={t("security.ruleId")}>
              <Typography.Text code>{event.rule_id ?? "—"}</Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label={t("security.ruleName")}>
              <strong>{event.rule_name}</strong>
            </Descriptions.Item>
            <Descriptions.Item label={t("security.action")}>
              <Tag color={actionColors[event.action] ?? "default"} style={{ color: "#fff" }}>
                {event.action}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label="Category">
              <Tag>{category}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label={t("security.method")}>
              <Tag>{event.method}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label={t("security.path")}>
              <Space>
                <Typography.Text
                  code
                  style={{ wordBreak: "break-all", fontSize: 12 }}
                >
                  {event.path}
                </Typography.Text>
                <Button
                  size="small"
                  type="text"
                  icon={<CopyOutlined />}
                  onClick={() => copyToClipboard(event.path, "Path")}
                />
              </Space>
            </Descriptions.Item>
            <Descriptions.Item label={<Space><GlobalOutlined /> {t("security.clientIP")}</Space>}>
              <Space>
                <Typography.Text code>{event.client_ip}</Typography.Text>
                <Button
                  size="small"
                  type="text"
                  icon={<CopyOutlined />}
                  onClick={() => copyToClipboard(event.client_ip, "IP")}
                />
              </Space>
            </Descriptions.Item>
            <Descriptions.Item label={t("security.country")}>
              {geo ? `${geo.country ?? "—"} / ${geo.isp ?? "—"}` : "—"}
            </Descriptions.Item>
          </Descriptions>
        </Card>

        {/* Detail */}
        {event.detail && (
          <Card
            size="small"
            title={t("eventDetail.detail")}
            extra={
              <Button
                size="small"
                icon={<CopyOutlined />}
                onClick={() => copyToClipboard(event.detail ?? "", t("eventDetail.copy"))}
              >
                {t("eventDetail.copy")}
              </Button>
            }
          >
            <Typography.Text
              style={{
                fontFamily: "ui-monospace, monospace",
                fontSize: 12,
                whiteSpace: "pre-wrap",
                wordBreak: "break-all",
                display: "block",
                maxHeight: 300,
                overflowY: "auto",
              }}
            >
              {event.detail}
            </Typography.Text>
          </Card>
        )}

        {/* Geo + Related */}
        <Row gutter={[12, 12]}>
          <Col xs={24} lg={12}>
            <Card size="small" title={t("eventDetail.geo")}>
              {geo && Object.keys(geo).length > 0 ? (
                <Descriptions column={1} size="small" bordered>
                  {geo.country && <Descriptions.Item label={t("security.country")}>{geo.country}</Descriptions.Item>}
                  {geo.province && <Descriptions.Item label="Province">{geo.province}</Descriptions.Item>}
                  {geo.city && <Descriptions.Item label={t("security.city")}>{geo.city}</Descriptions.Item>}
                  {geo.isp && <Descriptions.Item label={t("security.isp")}>{geo.isp}</Descriptions.Item>}
                  {geo.iso_code && <Descriptions.Item label="ISO">{geo.iso_code}</Descriptions.Item>}
                </Descriptions>
              ) : (
                <Typography.Text type="secondary">—</Typography.Text>
              )}
            </Card>
          </Col>
          <Col xs={24} lg={12}>
            <Card size="small" title={t("eventDetail.related")}>
              <Typography.Text strong style={{ display: "block", marginBottom: 8 }}>
                {t("eventDetail.sameIp")}
              </Typography.Text>
              <RelatedTable
                events={sameIpEvents}
                loading={sameIpQuery.query.isLoading}
                showIp={false}
              />
              <Typography.Text strong style={{ display: "block", margin: "12px 0 8px" }}>
                {t("eventDetail.sameRule")}
              </Typography.Text>
              <RelatedTable
                events={sameRuleEvents}
                loading={sameRuleQuery.query.isLoading}
                showIp
              />
            </Card>
          </Col>
        </Row>

        {/* Raw JSON */}
        <Collapse
          items={[
            {
              key: "raw",
              label: t("eventDetail.rawJson"),
              children: (
                <Space direction="vertical" style={{ width: "100%" }}>
                  <Button
                    size="small"
                    icon={<CopyOutlined />}
                    onClick={() =>
                      copyToClipboard(JSON.stringify(event, null, 2), t("eventDetail.copy"))
                    }
                  >
                    {t("eventDetail.copy")}
                  </Button>
                  <pre
                    style={{
                      fontFamily: "ui-monospace, monospace",
                      fontSize: 11,
                      background: "#f5f5f5",
                      padding: 12,
                      borderRadius: 4,
                      overflowX: "auto",
                      maxHeight: 400,
                    }}
                  >
                    {JSON.stringify(event, null, 2)}
                  </pre>
                </Space>
              ),
            },
          ]}
          defaultActiveKey={[]}
        />
      </Space>

      {/* Blocklist confirm modal */}
      <Modal
        open={blockModalOpen}
        onOk={handleAddToBlocklist}
        onCancel={() => setBlockModalOpen(false)}
        title={t("eventDetail.addToBlocklist")}
        okButtonProps={{ danger: true }}
        okText={t("common.confirm")}
      >
        <Typography.Text>
          {t("eventDetail.addToBlocklistConfirm", { ip: event.client_ip })}
        </Typography.Text>
      </Modal>
    </>
  );
};
