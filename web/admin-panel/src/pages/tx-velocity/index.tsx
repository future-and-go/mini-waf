import {
  Card,
  Row,
  Col,
  Typography,
  Space,
  Button,
  Table,
  Tag,
  Switch,
  Statistic,
  Descriptions,
} from "antd";
import { ReloadOutlined } from "@ant-design/icons";
import { useTable, useList } from "@refinedev/core";
import { Column } from "@ant-design/plots";
import type { ColumnsType } from "antd/es/table";
import { useTranslation } from "react-i18next";
import { useMemo, useState } from "react";
import type { SecurityEvent } from "../../types/api";
import { fmtDateTime } from "../../utils/format";

// ── Helpers ────────────────────────────────────────────────────────────────────

function actionColor(action: string): string {
  if (action === "block") return "red";
  if (action === "challenge") return "orange";
  return "default";
}

function rulePrefix(ruleId?: string): "TX-SEQ" | "TX-WITHDRAW" | "TX-LIMIT" | "TX-OTHER" {
  if (!ruleId) return "TX-OTHER";
  if (ruleId.startsWith("TX-SEQ")) return "TX-SEQ";
  if (ruleId.startsWith("TX-WITHDRAW")) return "TX-WITHDRAW";
  if (ruleId.startsWith("TX-LIMIT")) return "TX-LIMIT";
  return "TX-OTHER";
}

const PREFIX_COLOR: Record<string, string> = {
  "TX-SEQ": "blue",
  "TX-WITHDRAW": "orange",
  "TX-LIMIT": "purple",
  "TX-OTHER": "default",
};

// ── Page ───────────────────────────────────────────────────────────────────────

export const TxVelocityPage: React.FC = () => {
  const { t } = useTranslation();
  const [autoRefresh, setAutoRefresh] = useState(true);
  const interval = autoRefresh ? 30_000 : (false as const);

  // ── KPI counts (one useList per signal family, page_size=1 for bandwidth) ──

  const seqList = useList<SecurityEvent>({
    resource: "security-events",
    pagination: { mode: "server", currentPage: 1, pageSize: 1 },
    filters: [{ field: "rule_id_prefix", operator: "eq", value: "TX-SEQ-" }],
    queryOptions: { staleTime: 0, refetchInterval: interval },
  });

  const withdrawList = useList<SecurityEvent>({
    resource: "security-events",
    pagination: { mode: "server", currentPage: 1, pageSize: 1 },
    filters: [{ field: "rule_id_prefix", operator: "eq", value: "TX-WITHDRAW-" }],
    queryOptions: { staleTime: 0, refetchInterval: interval },
  });

  const limitList = useList<SecurityEvent>({
    resource: "security-events",
    pagination: { mode: "server", currentPage: 1, pageSize: 1 },
    filters: [{ field: "rule_id_prefix", operator: "eq", value: "TX-LIMIT-" }],
    queryOptions: { staleTime: 0, refetchInterval: interval },
  });

  const seqTotal = seqList.result?.total ?? 0;
  const withdrawTotal = withdrawList.result?.total ?? 0;
  const limitTotal = limitList.result?.total ?? 0;
  const grandTotal = seqTotal + withdrawTotal + limitTotal;

  // ── Events table (all TX- events via permanent filter) ─────────────────────

  const { tableQuery, result, currentPage, setCurrentPage, pageSize, setPageSize } =
    useTable<SecurityEvent>({
      resource: "security-events",
      pagination: { currentPage: 1, pageSize: 20, mode: "server" },
      filters: {
        permanent: [{ field: "rule_id_prefix", operator: "eq", value: "TX-" }],
      },
      queryOptions: { staleTime: 0, refetchInterval: interval },
    });

  const tableData = Array.isArray(result?.data) ? result.data : [];
  const tableTotal = result?.total ?? 0;

  // ── Chart data built from KPI totals ────────────────────────────────────────

  const chartData = useMemo(
    () => [
      { type: "TX-SEQ", count: seqTotal },
      { type: "TX-WITHDRAW", count: withdrawTotal },
      { type: "TX-LIMIT", count: limitTotal },
    ],
    [seqTotal, withdrawTotal, limitTotal],
  );

  function refetchAll() {
    seqList.query.refetch();
    withdrawList.query.refetch();
    limitList.query.refetch();
    tableQuery.refetch();
  }

  // ── Table columns ──────────────────────────────────────────────────────────

  const columns: ColumnsType<SecurityEvent> = [
    {
      title: t("security.time"),
      dataIndex: "created_at",
      width: 170,
      render: (v: string) => (
        <span style={{ color: "#8c8c8c", fontSize: 12 }}>{fmtDateTime(v)}</span>
      ),
    },
    {
      title: t("txVelocity.signalType"),
      dataIndex: "rule_id",
      width: 140,
      render: (v: string) => {
        const p = rulePrefix(v);
        return <Tag color={PREFIX_COLOR[p]}>{p}</Tag>;
      },
    },
    {
      title: t("security.ruleId"),
      dataIndex: "rule_id",
      width: 180,
      render: (v: string | undefined) =>
        v ? (
          <Typography.Text code copyable style={{ fontSize: 11 }}>
            {v}
          </Typography.Text>
        ) : (
          <span style={{ color: "#bfbfbf" }}>—</span>
        ),
    },
    {
      title: t("security.clientIP"),
      dataIndex: "client_ip",
      width: 140,
      render: (v) => (
        <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>{v}</span>
      ),
    },
    {
      title: t("security.action"),
      dataIndex: "action",
      width: 100,
      render: (v: string) => <Tag color={actionColor(v)}>{v}</Tag>,
    },
    {
      title: t("security.ruleName"),
      dataIndex: "rule_name",
      ellipsis: true,
    },
  ];

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      {/* Header */}
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <div>
          <Typography.Title level={4} style={{ margin: 0 }}>
            {t("txVelocity.title")}
          </Typography.Title>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {t("txVelocity.subtitle")}
          </Typography.Text>
        </div>
        <Space>
          <Switch
            checkedChildren="Auto"
            unCheckedChildren="Manual"
            checked={autoRefresh}
            onChange={setAutoRefresh}
          />
          <Button
            icon={<ReloadOutlined spin={tableQuery.isFetching} />}
            onClick={refetchAll}
          >
            {t("common.refresh")}
          </Button>
        </Space>
      </Space>

      {/* KPI row */}
      <Row gutter={[16, 16]}>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic
              title={t("txVelocity.seqCount")}
              value={seqTotal}
              valueStyle={{ color: "#1677ff" }}
              loading={seqList.query.isLoading}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic
              title={t("txVelocity.withdrawCount")}
              value={withdrawTotal}
              valueStyle={{ color: "#fa8c16" }}
              loading={withdrawList.query.isLoading}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic
              title={t("txVelocity.limitCount")}
              value={limitTotal}
              valueStyle={{ color: "#722ed1" }}
              loading={limitList.query.isLoading}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic
              title={t("txVelocity.totalCount")}
              value={grandTotal}
              valueStyle={{ color: "#cf1322" }}
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        {/* Signal distribution chart */}
        <Col xs={24} lg={12}>
          <Card title={t("txVelocity.distribution")}>
            {grandTotal > 0 ? (
              <Column
                data={chartData}
                xField="type"
                yField="count"
                height={220}
                animate={false}
              />
            ) : (
              <div
                style={{
                  height: 220,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                }}
              >
                <Typography.Text type="secondary">{t("txVelocity.noEvents")}</Typography.Text>
              </div>
            )}
          </Card>
        </Col>

        {/* Config thresholds (read-only, no REST API for FR-012 config) */}
        <Col xs={24} lg={12}>
          <Card
            title={t("txVelocity.configInfo")}
            extra={<Tag color="cyan">configs/tx-velocity.yaml</Tag>}
          >
            <Descriptions column={1} size="small" bordered>
              <Descriptions.Item label={<Tag color="blue">TX-SEQ-*</Tag>}>
                {t("txVelocity.seqThreshold")}
              </Descriptions.Item>
              <Descriptions.Item label={<Tag color="orange">TX-WITHDRAW-*</Tag>}>
                {t("txVelocity.withdrawThreshold")}
              </Descriptions.Item>
              <Descriptions.Item label={<Tag color="purple">TX-LIMIT-*</Tag>}>
                {t("txVelocity.limitThreshold")}
              </Descriptions.Item>
            </Descriptions>
            <Typography.Text
              type="secondary"
              style={{ fontSize: 12, marginTop: 12, display: "block" }}
            >
              {t("txVelocity.configEditHint")}
            </Typography.Text>
          </Card>
        </Col>
      </Row>

      {/* Recent TX events table */}
      <Card size="small" title={t("txVelocity.recentEvents")}>
        <Table
          rowKey="id"
          size="small"
          dataSource={tableData}
          columns={columns}
          loading={tableQuery.isLoading}
          pagination={{
            current: currentPage,
            pageSize,
            total: tableTotal,
            onChange: (p, ps) => {
              setCurrentPage(p);
              setPageSize(ps);
            },
            showSizeChanger: true,
            pageSizeOptions: [20, 50, 100],
            showTotal: (n) => `${t("common.total")}: ${n}`,
          }}
          locale={{ emptyText: t("txVelocity.noEvents") }}
          scroll={{ x: 800 }}
        />
      </Card>
    </Space>
  );
};
