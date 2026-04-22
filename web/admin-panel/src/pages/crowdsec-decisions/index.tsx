import {
  Card,
  Table,
  Tag,
  Input,
  Button,
  Space,
  Typography,
  App,
  Popconfirm,
} from "antd";
import { ReloadOutlined } from "@ant-design/icons";
import { useCustom, useCustomMutation } from "@refinedev/core";
import type { ColumnsType } from "antd/es/table";
import { useTranslation } from "react-i18next";
import { useMemo, useState } from "react";
import type { CrowdsecDecision } from "../../types/api";

interface DecisionsResponse {
  decisions?: CrowdsecDecision[];
  total?: number;
}

const typeColor = (t_: string): string =>
  ({ ban: "red", captcha: "gold", throttle: "orange" }[t_] ?? "default");

export const CrowdsecDecisionsPage: React.FC = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();

  const { result, query } = useCustom<DecisionsResponse>({
    url: "/api/crowdsec/decisions",
    method: "get",
    queryOptions: { staleTime: 5_000, refetchInterval: 10_000 },
  });
  const { mutate: del } = useCustomMutation();
  const refetch = query.refetch;
  const isLoading = query.isLoading;
  const isFetching = query.isFetching;

  const [valueFilter, setValueFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [scenarioFilter, setScenarioFilter] = useState("");

  const rawDecisions = result?.data?.decisions;
  const decisions = Array.isArray(rawDecisions) ? rawDecisions : [];
  const total = result?.data?.total ?? 0;

  const filtered = useMemo(
    () =>
      decisions.filter((d) => {
        if (valueFilter && !d.value.includes(valueFilter)) return false;
        if (typeFilter && !d.type_.includes(typeFilter)) return false;
        if (scenarioFilter && !d.scenario.includes(scenarioFilter)) return false;
        return true;
      }),
    [decisions, valueFilter, typeFilter, scenarioFilter],
  );

  const onDelete = (id: number) =>
    del(
      { url: `/api/crowdsec/decisions/${id}`, method: "delete", values: {} },
      {
        onSuccess: () => {
          message.success("OK");
          refetch();
        },
        onError: (err) => message.error(err.message),
      },
    );

  const columns: ColumnsType<CrowdsecDecision> = [
    { title: t("crowdsec.value"), dataIndex: "value", render: (v) => <span style={{ fontFamily: "ui-monospace, monospace" }}>{v}</span> },
    { title: t("crowdsec.type"), dataIndex: "type_", width: 100, render: (v: string) => <Tag color={typeColor(v)}>{v}</Tag> },
    { title: t("crowdsec.scenario"), dataIndex: "scenario", ellipsis: true },
    { title: t("crowdsec.origin"), dataIndex: "origin", width: 120 },
    { title: t("crowdsec.scope"), dataIndex: "scope", width: 100 },
    { title: t("crowdsec.duration"), dataIndex: "duration", width: 110, render: (v?: string) => v ?? "—" },
    {
      title: "",
      key: "ops",
      width: 90,
      render: (_v, r) => (
        <Popconfirm title={t("crowdsec.confirmDeleteDecision", { id: r.id })} onConfirm={() => onDelete(r.id)}>
          <Button size="small" danger>
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
          {t("crowdsec.decisionsTitle")}
        </Typography.Title>
        <Space>
          <Typography.Text type="secondary">
            {total} {t("crowdsec.activeDecisions")}
          </Typography.Text>
          <Button icon={<ReloadOutlined spin={isFetching} />} onClick={() => refetch()} type="primary">
            {t("common.refresh")}
          </Button>
        </Space>
      </Space>

      <Card size="small">
        <Space wrap style={{ marginBottom: 12 }}>
          <Input placeholder={t("crowdsec.filterByIp")} value={valueFilter} onChange={(e) => setValueFilter(e.target.value)} style={{ width: 220 }} allowClear />
          <Input placeholder={t("crowdsec.filterByType")} value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} style={{ width: 200 }} allowClear />
          <Input placeholder={t("crowdsec.filterByScenario")} value={scenarioFilter} onChange={(e) => setScenarioFilter(e.target.value)} style={{ width: 240 }} allowClear />
        </Space>

        <Table
          rowKey="id"
          size="small"
          dataSource={filtered}
          columns={columns}
          loading={isLoading}
          pagination={{ pageSize: 50 }}
          locale={{ emptyText: t("crowdsec.noDecisions") }}
        />
      </Card>
    </Space>
  );
};
