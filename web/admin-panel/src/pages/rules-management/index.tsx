import {
  Alert,
  Button,
  Card,
  Col,
  Drawer,
  Form,
  Input,
  Modal,
  Progress,
  Row,
  Select,
  Space,
  Statistic,
  Table,
  Tag,
  Typography,
  App,
} from "antd";
import { useCustom, useCustomMutation } from "@refinedev/core";
import type { ColumnsType } from "antd/es/table";
import { useTranslation } from "react-i18next";
import { useEffect, useMemo, useState } from "react";
import type { RegistryRule } from "../../types/api";

interface FailedRule {
  rule_id: string;
  file: string;
  reason: string;
}

interface RegistryResponse {
  rules?: RegistryRule[];
  total?: number;
  enabled?: number;
  disabled?: number;
  failed_rules?: FailedRule[];
}

const severityColor = (s?: string): string =>
  ({ critical: "red", high: "orange", medium: "gold", low: "blue" }[s ?? ""] ?? "default");

const actionColor = (a: string): string =>
  ({ block: "red", log: "gold", allow: "green" }[a] ?? "default");

// Normalize response — backend may return top-level {rules,total,...} or wrapped {data:{rules,...}}
function normalizeRegistryResponse(
  result: RegistryResponse | { data: RegistryResponse } | undefined,
): RegistryResponse {
  if (!result) return {};
  if ("rules" in result) return result as RegistryResponse;
  if ("data" in result && result.data && "rules" in result.data) return result.data;
  return {};
}

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
  const { mutateAsync: toggleAsync } = useCustomMutation();
  const { mutate: importRules } = useCustomMutation();
  const refetch = query.refetch;
  const isLoading = query.isLoading;
  const reloading = reloadMutation.isPending;

  // Handle both envelope shapes
  const normalized = normalizeRegistryResponse(
    result?.data as RegistryResponse | { data: RegistryResponse } | undefined,
  );
  const rules: RegistryRule[] = Array.isArray(normalized.rules) ? normalized.rules : [];

  const [search, setSearch] = useState("");
  const [filterCategory, setFilterCategory] = useState<string | undefined>();
  const [filterSource, setFilterSource] = useState<string | undefined>();
  const [filterStatus, setFilterStatus] = useState<string | undefined>();
  const [pagination, setPagination] = useState({ current: 1, pageSize: 20 });
  const [selected, setSelected] = useState<RegistryRule | null>(null);
  const [importOpen, setImportOpen] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);
  const [importForm] = Form.useForm<{ source: string; format: string }>();

  // Bulk selection
  const [selectedRowKeys, setSelectedRowKeys] = useState<string[]>([]);
  const [bulkProgress, setBulkProgress] = useState<{ running: boolean; done: number; total: number }>({
    running: false,
    done: 0,
    total: 0,
  });

  useEffect(() => {
    setPagination((p) => ({ ...p, current: 1 }));
  }, [search, filterCategory, filterSource, filterStatus]);

  const failedRules: FailedRule[] = Array.isArray(normalized.failed_rules) ? normalized.failed_rules : [];

  const stats = useMemo(() => {
    const total = normalized.total ?? rules.length;
    const enabled = normalized.enabled ?? rules.filter((r) => r.enabled).length;
    const disabled = normalized.disabled ?? (total - enabled);
    const cats = new Set(rules.map((r) => r.category));
    return { total, enabled, disabled, categories: cats.size };
  }, [rules, normalized]);

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
      {
        onSuccess: () => { message.success("OK"); refetch(); },
        onError: (err) => message.error(err.message),
      },
    );

  const onToggle = (r: RegistryRule) =>
    toggle(
      { url: `/api/rules/registry/${r.id}`, method: "patch", values: { enabled: !r.enabled } },
      { onSuccess: () => refetch(), onError: (err) => message.error(err.message) },
    );

  const onImport = async () => {
    setImportError(null);
    let v: { source: string; format: string };
    try {
      v = await importForm.validateFields();
    } catch {
      return;
    }
    importRules(
      { url: "/api/rules/import", method: "post", values: v },
      {
        onSuccess: () => {
          message.success("OK");
          setImportOpen(false);
          setImportError(null);
          refetch();
        },
        onError: (err) => {
          // Show full backend error (e.g. "BadRequest: Invalid YAML: ...")
          setImportError(err.message);
        },
      },
    );
  };

  const onBulkToggle = async (enabled: boolean) => {
    const keys = [...selectedRowKeys];
    const CHUNK = 10;
    setBulkProgress({ running: true, done: 0, total: keys.length });
    let successCount = 0;
    let failCount = 0;

    for (let i = 0; i < keys.length; i += CHUNK) {
      const chunk = keys.slice(i, i + CHUNK);
      const results = await Promise.allSettled(
        chunk.map((id) =>
          toggleAsync({ url: `/api/rules/registry/${id}`, method: "patch", values: { enabled } }),
        ),
      );
      successCount += results.filter((r) => r.status === "fulfilled").length;
      failCount += results.filter((r) => r.status === "rejected").length;
      setBulkProgress({ running: true, done: i + chunk.length, total: keys.length });
    }

    setBulkProgress({ running: false, done: keys.length, total: keys.length });

    if (failCount === 0) {
      message.success(t(enabled ? "rules.bulkEnable" : "rules.bulkDisable") + ` (${successCount})`);
    } else {
      message.warning(`${successCount} OK, ${failCount} failed`);
    }
    setSelectedRowKeys([]);
    refetch();
  };

  const onBulkExport = () => {
    const selectedRules = rules.filter((r) => selectedRowKeys.includes(r.id));
    const json = JSON.stringify(selectedRules, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `rules-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const columns: ColumnsType<RegistryRule> = [
    {
      title: t("rules.ruleId"),
      dataIndex: "id",
      width: 130,
      render: (v: string) => (
        <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>{v}</span>
      ),
    },
    { title: t("common.name"), dataIndex: "name" },
    {
      title: t("rules.category"),
      dataIndex: "category",
      width: 120,
      render: (v: string) => <Tag color="blue">{v}</Tag>,
    },
    {
      title: t("common.source"),
      dataIndex: "source",
      width: 140,
      render: (v: string) => <span style={{ fontSize: 11, color: "#8c8c8c" }}>{v}</span>,
    },
    {
      title: t("rules.severity"),
      dataIndex: "severity",
      width: 100,
      render: (v?: string) => (v ? <Tag color={severityColor(v)}>{v}</Tag> : null),
    },
    {
      title: t("security.action"),
      dataIndex: "action",
      width: 90,
      render: (v: string) => <Tag color={actionColor(v)}>{v}</Tag>,
    },
    {
      title: t("common.status"),
      dataIndex: "enabled",
      width: 110,
      render: (_v, r) => (
        <Button
          size="small"
          type="link"
          onClick={(e) => { e.stopPropagation(); onToggle(r); }}
        >
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
        <Col xs={12} lg={6}>
          <Card size="small"><Statistic title={t("rules.totalRules")} value={stats.total} /></Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card size="small">
            <Statistic title={t("rules.enabledRules")} value={stats.enabled} valueStyle={{ color: "#52c41a" }} />
          </Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card size="small">
            <Statistic title={t("rules.disabledRules")} value={stats.disabled} valueStyle={{ color: "#bfbfbf" }} />
          </Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card size="small">
            <Statistic title={t("rules.categories")} value={stats.categories} valueStyle={{ color: "#1677ff" }} />
          </Card>
        </Col>
      </Row>

      {failedRules.length > 0 && (
        <Alert
          type="error"
          showIcon
          message={`${failedRules.length} rule(s) failed to load`}
          description={
            <ul style={{ margin: 0, paddingLeft: 16 }}>
              {failedRules.map((f) => (
                <li key={f.rule_id}>
                  <Tag color="red">{f.reason}</Tag>{" "}
                  <Typography.Text code style={{ fontSize: 11 }}>{f.rule_id}</Typography.Text>
                  {f.file ? <Typography.Text type="secondary" style={{ fontSize: 11 }}> ({f.file})</Typography.Text> : null}
                </li>
              ))}
            </ul>
          }
        />
      )}

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

        {/* Bulk action bar */}
        {selectedRowKeys.length > 0 && (
          <Space style={{ marginBottom: 12 }}>
            <Typography.Text>{selectedRowKeys.length} selected</Typography.Text>
            <Button
              size="small"
              onClick={() => void onBulkToggle(true)}
              disabled={bulkProgress.running}
            >
              {t("rules.bulkEnable")}
            </Button>
            <Button
              size="small"
              onClick={() => void onBulkToggle(false)}
              disabled={bulkProgress.running}
            >
              {t("rules.bulkDisable")}
            </Button>
            <Button size="small" onClick={onBulkExport} disabled={bulkProgress.running}>
              {t("rules.bulkExport")}
            </Button>
            <Button
              size="small"
              type="text"
              onClick={() => setSelectedRowKeys([])}
            >
              {t("common.cancel")}
            </Button>
          </Space>
        )}
        {bulkProgress.running && (
          <Progress
            percent={Math.round((bulkProgress.done / bulkProgress.total) * 100)}
            size="small"
            style={{ marginBottom: 8 }}
          />
        )}

        <Table
          rowKey="id"
          size="small"
          dataSource={filtered}
          columns={columns}
          loading={isLoading}
          rowSelection={{
            selectedRowKeys,
            onChange: (keys) => setSelectedRowKeys(keys as string[]),
          }}
          pagination={{
            current: pagination.current,
            pageSize: pagination.pageSize,
            total: filtered.length,
            showSizeChanger: true,
            pageSizeOptions: ["20", "50", "100"],
            showTotal: (total, range) => `${range[0]}-${range[1]} / ${total}`,
            onChange: (page, pageSize) => setPagination({ current: page, pageSize }),
          }}
          onRow={(r) => ({ onClick: () => setSelected(r), style: { cursor: "pointer" } })}
          locale={{ emptyText: t("rules.noRulesFound") }}
        />
      </Card>

      {/* Rule detail drawer */}
      <Drawer
        title={selected?.name}
        placement="right"
        width={520}
        open={!!selected}
        onClose={() => setSelected(null)}
        aria-label="Rule detail"
      >
        {selected && (
          <Space direction="vertical" size="middle" style={{ width: "100%" }}>
            <div>
              <Typography.Text type="secondary">ID: </Typography.Text>
              <Typography.Text code>{selected.id}</Typography.Text>
            </div>
            <Space size="large" wrap>
              <span>
                <Typography.Text type="secondary">{t("rules.category")}: </Typography.Text>
                {selected.category}
              </span>
              <span>
                <Typography.Text type="secondary">{t("common.source")}: </Typography.Text>
                {selected.source}
              </span>
              <span>
                <Typography.Text type="secondary">{t("security.action")}: </Typography.Text>
                <Tag color={actionColor(selected.action)}>{selected.action}</Tag>
              </span>
              <span>
                <Typography.Text type="secondary">{t("rules.severity")}: </Typography.Text>
                {selected.severity ?? "N/A"}
              </span>
            </Space>
            {selected.file && (
              <div>
                <Typography.Text type="secondary">File: </Typography.Text>
                <Typography.Text code style={{ fontSize: 11 }}>
                  {selected.file}
                </Typography.Text>
              </div>
            )}
            {selected.description && (
              <div>
                <Typography.Text type="secondary">{t("common.description")}:</Typography.Text>
                <Typography.Paragraph>{selected.description}</Typography.Paragraph>
              </div>
            )}
            {selected.pattern && (
              <div>
                <Typography.Text type="secondary">{t("botManagement.pattern")}:</Typography.Text>
                <pre
                  style={{
                    background: "#fafafa",
                    padding: 8,
                    borderRadius: 4,
                    fontSize: 11,
                    overflowX: "auto",
                  }}
                >
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
            <Button
              onClick={() => {
                onToggle(selected);
                setSelected(null);
              }}
            >
              {selected.enabled ? t("rules.disable") : t("rules.enable")}
            </Button>
          </Space>
        )}
      </Drawer>

      {/* Import modal */}
      <Modal
        title={t("rules.importRules")}
        open={importOpen}
        onCancel={() => { setImportOpen(false); setImportError(null); }}
        onOk={() => void onImport()}
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
        {importError && (
          <Alert type="error" showIcon message={importError} style={{ marginTop: 8 }} />
        )}
      </Modal>
    </Space>
  );
};
