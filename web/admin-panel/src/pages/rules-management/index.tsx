import {
  Card,
  Row,
  Col,
  Statistic,
  Input,
  Select,
  Button,
  Space,
  Table,
  Tag,
  Drawer,
  Typography,
  Modal,
  Form,
  App,
} from "antd";
import { useCustom, useCustomMutation } from "@refinedev/core";
import type { ColumnsType } from "antd/es/table";
import { useTranslation } from "react-i18next";
import { useMemo, useState } from "react";
import type { RegistryRule } from "../../types/api";

interface RegistryResponse {
  rules?: RegistryRule[];
  enabled?: number;
  disabled?: number;
}

const severityColor = (s?: string): string =>
  ({ critical: "red", high: "orange", medium: "gold", low: "blue" }[s ?? ""] ?? "default");

const actionColor = (a: string): string =>
  ({ block: "red", log: "gold", allow: "green" }[a] ?? "default");

export const RulesManagementPage: React.FC = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();

  const { result, query } = useCustom<RegistryResponse>({
    url: "/api/rules/registry",
    method: "get",
    queryOptions: { staleTime: 60_000 },
  });
  const { mutate: reload, mutation: reloadMutation } = useCustomMutation();
  const { mutate: toggle } = useCustomMutation();
  const { mutate: importRules } = useCustomMutation();
  const refetch = query.refetch;
  const isLoading = query.isLoading;
  const reloading = reloadMutation.isPending;

  const rawRules = result?.data?.rules;
  const rules: RegistryRule[] = Array.isArray(rawRules) ? rawRules : [];

  const [search, setSearch] = useState("");
  const [filterCategory, setFilterCategory] = useState<string | undefined>();
  const [filterSource, setFilterSource] = useState<string | undefined>();
  const [filterStatus, setFilterStatus] = useState<string | undefined>();
  const [selected, setSelected] = useState<RegistryRule | null>(null);
  const [importOpen, setImportOpen] = useState(false);
  const [importForm] = Form.useForm<{ source: string; format: string }>();

  const stats = useMemo(() => {
    const total = rules.length;
    const enabled = rules.filter((r) => r.enabled).length;
    const cats = new Set(rules.map((r) => r.category));
    return { total, enabled, disabled: total - enabled, categories: cats.size };
  }, [rules]);

  const categories = useMemo(() => [...new Set(rules.map((r) => r.category))].sort(), [rules]);
  const sources = useMemo(() => [...new Set(rules.map((r) => r.source))].sort(), [rules]);

  const filtered = useMemo(() => {
    let list = rules;
    if (search) {
      const q = search.toLowerCase();
      list = list.filter(
        (r) =>
          r.id.toLowerCase().includes(q) ||
          r.name.toLowerCase().includes(q) ||
          r.description?.toLowerCase().includes(q),
      );
    }
    if (filterCategory) list = list.filter((r) => r.category === filterCategory);
    if (filterSource) list = list.filter((r) => r.source === filterSource);
    if (filterStatus === "enabled") list = list.filter((r) => r.enabled);
    if (filterStatus === "disabled") list = list.filter((r) => !r.enabled);
    return list;
  }, [rules, search, filterCategory, filterSource, filterStatus]);

  const onReload = () =>
    reload(
      { url: "/api/rules/reload", method: "post", values: {} },
      { onSuccess: () => { message.success("OK"); refetch(); }, onError: (err) => message.error(err.message) },
    );

  const onToggle = (r: RegistryRule) =>
    toggle(
      { url: `/api/rules/registry/${r.id}`, method: "patch", values: { enabled: !r.enabled } },
      { onSuccess: () => refetch(), onError: (err) => message.error(err.message) },
    );

  const onImport = async () => {
    const v = await importForm.validateFields();
    importRules(
      { url: "/api/rules/import", method: "post", values: v },
      {
        onSuccess: () => {
          message.success("OK");
          setImportOpen(false);
          refetch();
        },
        onError: (err) => message.error(err.message),
      },
    );
  };

  const columns: ColumnsType<RegistryRule> = [
    { title: t("rules.ruleId"), dataIndex: "id", width: 130, render: (v) => <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>{v}</span> },
    { title: t("common.name"), dataIndex: "name" },
    { title: t("rules.category"), dataIndex: "category", width: 120, render: (v) => <Tag color="blue">{v}</Tag> },
    { title: t("common.source"), dataIndex: "source", width: 140, render: (v) => <span style={{ fontSize: 11, color: "#8c8c8c" }}>{v}</span> },
    { title: t("rules.severity"), dataIndex: "severity", width: 100, render: (v?: string) => v ? <Tag color={severityColor(v)}>{v}</Tag> : null },
    { title: t("security.action"), dataIndex: "action", width: 90, render: (v: string) => <Tag color={actionColor(v)}>{v}</Tag> },
    {
      title: t("common.status"),
      dataIndex: "enabled",
      width: 110,
      render: (_v, r) => (
        <Button size="small" type="link" onClick={(e) => { e.stopPropagation(); onToggle(r); }}>
          {r.enabled ? t("rules.disable") : t("rules.enable")}
        </Button>
      ),
    },
  ];

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <div>
          <Typography.Title level={4} style={{ margin: 0 }}>
            {t("rules.title")}
          </Typography.Title>
          <Typography.Text type="secondary">{t("rules.manageRules")}</Typography.Text>
        </div>
        <Space>
          <Button onClick={onReload} loading={reloading}>
            {t("rules.reloadRules")}
          </Button>
          <Button type="primary" onClick={() => setImportOpen(true)}>
            {t("rules.importRules")}
          </Button>
        </Space>
      </Space>

      <Row gutter={[12, 12]}>
        <Col xs={12} lg={6}><Card size="small"><Statistic title={t("rules.totalRules")} value={stats.total} /></Card></Col>
        <Col xs={12} lg={6}><Card size="small"><Statistic title={t("rules.enabledRules")} value={stats.enabled} valueStyle={{ color: "#52c41a" }} /></Card></Col>
        <Col xs={12} lg={6}><Card size="small"><Statistic title={t("rules.disabledRules")} value={stats.disabled} valueStyle={{ color: "#bfbfbf" }} /></Card></Col>
        <Col xs={12} lg={6}><Card size="small"><Statistic title={t("rules.categories")} value={stats.categories} valueStyle={{ color: "#1677ff" }} /></Card></Col>
      </Row>

      <Card size="small">
        <Space wrap style={{ marginBottom: 12 }}>
          <Input
            placeholder={t("rules.searchRules")}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{ width: 220 }}
            allowClear
          />
          <Select
            placeholder={t("rules.allCategories")}
            value={filterCategory}
            onChange={setFilterCategory}
            allowClear
            style={{ width: 160 }}
            options={categories.map((c) => ({ value: c, label: c }))}
          />
          <Select
            placeholder={t("rules.allSources")}
            value={filterSource}
            onChange={setFilterSource}
            allowClear
            style={{ width: 160 }}
            options={sources.map((s) => ({ value: s, label: s }))}
          />
          <Select
            placeholder={t("rules.allStatus")}
            value={filterStatus}
            onChange={setFilterStatus}
            allowClear
            style={{ width: 130 }}
            options={[
              { value: "enabled", label: t("common.enabled") },
              { value: "disabled", label: t("common.disabled") },
            ]}
          />
        </Space>
        <Table
          rowKey="id"
          size="small"
          dataSource={filtered}
          columns={columns}
          loading={isLoading}
          pagination={{ pageSize: 20, showSizeChanger: true, pageSizeOptions: [20, 50, 100] }}
          onRow={(r) => ({ onClick: () => setSelected(r), style: { cursor: "pointer" } })}
          locale={{ emptyText: t("rules.noRulesFound") }}
        />
      </Card>

      <Drawer
        title={selected?.name}
        placement="right"
        width={520}
        open={!!selected}
        onClose={() => setSelected(null)}
      >
        {selected && (
          <Space direction="vertical" size="middle" style={{ width: "100%" }}>
            <div>
              <Typography.Text type="secondary">ID: </Typography.Text>
              <Typography.Text code>{selected.id}</Typography.Text>
            </div>
            <Space size="large" wrap>
              <span><Typography.Text type="secondary">{t("rules.category")}: </Typography.Text>{selected.category}</span>
              <span><Typography.Text type="secondary">{t("common.source")}: </Typography.Text>{selected.source}</span>
              <span><Typography.Text type="secondary">{t("security.action")}: </Typography.Text><Tag color={actionColor(selected.action)}>{selected.action}</Tag></span>
              <span><Typography.Text type="secondary">{t("rules.severity")}: </Typography.Text>{selected.severity ?? "N/A"}</span>
            </Space>
            {selected.description && (
              <div>
                <Typography.Text type="secondary">{t("common.description")}:</Typography.Text>
                <Typography.Paragraph>{selected.description}</Typography.Paragraph>
              </div>
            )}
            {selected.pattern && (
              <div>
                <Typography.Text type="secondary">{t("botManagement.pattern")}:</Typography.Text>
                <pre style={{ background: "#fafafa", padding: 8, borderRadius: 4, fontSize: 11, overflowX: "auto" }}>
                  {selected.pattern}
                </pre>
              </div>
            )}
            {selected.tags?.length ? (
              <div>
                <Typography.Text type="secondary">{t("botManagement.tags")}: </Typography.Text>
                {selected.tags.map((tag) => (
                  <Tag key={tag}>{tag}</Tag>
                ))}
              </div>
            ) : null}
            <Button onClick={() => { onToggle(selected); setSelected(null); }}>
              {selected.enabled ? t("rules.disable") : t("rules.enable")}
            </Button>
          </Space>
        )}
      </Drawer>

      <Modal
        title={t("rules.importRules")}
        open={importOpen}
        onCancel={() => setImportOpen(false)}
        onOk={onImport}
        okText={t("common.import")}
        cancelText={t("common.cancel")}
        destroyOnClose
      >
        <Form form={importForm} layout="vertical" initialValues={{ format: "yaml" }}>
          <Form.Item name="source" label="Source (file path or URL)" rules={[{ required: true }]}>
            <Input placeholder="rules/custom.yaml or https://..." />
          </Form.Item>
          <Form.Item name="format" label={t("common.format")}>
            <Select
              options={[
                { value: "yaml", label: "YAML" },
                { value: "json", label: "JSON" },
                { value: "modsec", label: "ModSecurity" },
              ]}
            />
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  );
};
