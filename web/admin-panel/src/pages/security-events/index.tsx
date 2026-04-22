import { Card, Table, Tag, Space, Input, Select, Button, Typography, Switch } from "antd";
import { ReloadOutlined } from "@ant-design/icons";
import { useTable } from "@refinedev/core";
import type { ColumnsType } from "antd/es/table";
import { useTranslation } from "react-i18next";
import { useState } from "react";
import type { SecurityEvent } from "../../types/api";
import { fmtDateTime } from "../../utils/format";

export const SecurityEventsPage: React.FC = () => {
  const { t } = useTranslation();
  const [hostCode, setHostCode] = useState("");
  const [clientIp, setClientIp] = useState("");
  const [action, setAction] = useState<string | undefined>();
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Server-side pagination is the only sane default for SecurityEvents:
  // the table can be millions of rows. Filters propagate as `?host_code=...`
  // through the data provider's filter→params flattening.
  const { tableQuery, result, currentPage, setCurrentPage, pageSize, setPageSize, setFilters } = useTable<SecurityEvent>({
    resource: "security-events",
    pagination: { currentPage: 1, pageSize: 20, mode: "server" },
    queryOptions: {
      staleTime: 0,
      refetchInterval: autoRefresh ? 10_000 : false,
    },
  });

  const applyFilters = () => {
    setFilters(
      [
        { field: "host_code", operator: "eq", value: hostCode || undefined },
        { field: "client_ip", operator: "eq", value: clientIp || undefined },
        { field: "action", operator: "eq", value: action || undefined },
      ],
      "replace",
    );
    setCurrentPage(1);
  };

  const data = Array.isArray(result?.data) ? result.data : [];
  const total = result?.total ?? 0;

  const columns: ColumnsType<SecurityEvent> = [
    { title: t("security.time"), dataIndex: "created_at", width: 170, render: (v: string) => <span style={{ color: "#8c8c8c", fontSize: 12 }}>{fmtDateTime(v)}</span> },
    { title: t("security.clientIP"), dataIndex: "client_ip", width: 140, render: (v) => <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>{v}</span> },
    { title: t("security.method"), dataIndex: "method", width: 80, render: (v) => <Tag>{v}</Tag> },
    { title: t("security.path"), dataIndex: "path", ellipsis: true, render: (v) => <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }} title={v}>{v}</span> },
    { title: t("security.ruleName"), dataIndex: "rule_name", width: 200, ellipsis: true },
    { title: t("security.action"), dataIndex: "action", width: 90, render: (v: string) => <Tag color={v === "block" ? "red" : "green"}>{v}</Tag> },
  ];

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <Typography.Title level={4} style={{ margin: 0 }}>
          {t("security.title")}
        </Typography.Title>
        <Space>
          <Switch
            checkedChildren="Auto"
            unCheckedChildren="Manual"
            checked={autoRefresh}
            onChange={setAutoRefresh}
          />
          <Button icon={<ReloadOutlined spin={tableQuery.isFetching} />} onClick={() => tableQuery.refetch()}>
            {t("common.refresh")}
          </Button>
        </Space>
      </Space>

      <Card size="small">
        <Space wrap style={{ marginBottom: 12 }}>
          <Input
            placeholder={t("security.hostCode")}
            value={hostCode}
            onChange={(e) => setHostCode(e.target.value)}
            style={{ width: 180 }}
            onPressEnter={applyFilters}
          />
          <Input
            placeholder={t("security.clientIP")}
            value={clientIp}
            onChange={(e) => setClientIp(e.target.value)}
            style={{ width: 180 }}
            onPressEnter={applyFilters}
          />
          <Select
            placeholder={t("security.allActions")}
            value={action}
            onChange={setAction}
            allowClear
            style={{ width: 140 }}
            options={[
              { value: "block", label: t("security.block") },
              { value: "allow", label: t("security.allow") },
            ]}
          />
          <Button type="primary" onClick={applyFilters}>
            {t("security.filter")}
          </Button>
        </Space>

        <Table
          rowKey="id"
          size="small"
          dataSource={data}
          columns={columns}
          loading={tableQuery.isLoading}
          pagination={{
            current: currentPage,
            pageSize,
            total,
            onChange: (p, ps) => {
              setCurrentPage(p);
              setPageSize(ps);
            },
            showSizeChanger: true,
            pageSizeOptions: [20, 50, 100, 200],
            showTotal: (n) => `${t("common.total")}: ${n}`,
          }}
          locale={{ emptyText: t("security.noEvents") }}
          scroll={{ x: 800 }}
        />
      </Card>
    </Space>
  );
};
