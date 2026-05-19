import {
  Card,
  Button,
  Space,
  Table,
  Tag,
  Typography,
  Popconfirm,
  Select,
  Switch,
  App,
  Tooltip,
} from "antd";
import {
  CopyOutlined,
  EditOutlined,
  PlusOutlined,
} from "@ant-design/icons";
import { useTable, useDelete, useUpdate } from "@refinedev/core";
import type { ColumnsType } from "antd/es/table";
import { useTranslation } from "react-i18next";
import { useState } from "react";
import type { CustomRule, RuleAction } from "../../types/api";
import { CustomRuleEditorDrawer } from "./CustomRuleEditorDrawer";

// ── Action color helper ───────────────────────────────────────────────────────

const actionColor = (a: string): string =>
  ({ block: "red", allow: "green", log: "gold", challenge: "blue" })[a] ?? "default";

// ── Condition mode badge ──────────────────────────────────────────────────────

const conditionModeBadge = (r: CustomRule) => {
  if (r.match_tree) return <Tag color="purple">{<span>tree</span>}</Tag>;
  if (r.script) return <Tag color="cyan">rhai</Tag>;
  if (r.conditions?.length) return <Tag>flat</Tag>;
  return <Tag color="default">—</Tag>;
};

// ── Page ──────────────────────────────────────────────────────────────────────

type DrawerState =
  | { open: false }
  | { open: true; mode: "create"; initial?: undefined }
  | { open: true; mode: "edit"; initial: CustomRule }
  | { open: true; mode: "create"; initial: CustomRule }; // duplicate

export const CustomRulesPage: React.FC = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();

  const [filterHostCode, setFilterHostCode] = useState<string | undefined>();
  const [filterAction, setFilterAction] = useState<RuleAction | undefined>();
  const [filterEnabled, setFilterEnabled] = useState<string | undefined>();
  const [drawerState, setDrawerState] = useState<DrawerState>({ open: false });

  const { tableQuery, result } = useTable<CustomRule>({
    resource: "custom-rules",
    pagination: { mode: "off" },
    queryOptions: { staleTime: 30_000 },
  });

  const { mutate: del } = useDelete();
  // BACKEND-GAP: PATCH /api/custom-rules/{id} for toggle-enabled.
  // Verify crates/waf-api/src/rules_api.rs has set_custom_rule_enabled / PATCH handler.
  // If only PUT is supported, use full-replace: useUpdate with method "put" + current rule data.
  const { mutate: toggleEnabled } = useUpdate();

  const allRules: CustomRule[] = Array.isArray(result?.data) ? (result.data as CustomRule[]) : [];

  // Client-side filtering (no server-side filter params for this resource)
  const filtered = allRules.filter((r) => {
    if (filterHostCode && r.host_code !== filterHostCode) return false;
    if (filterAction && r.action !== filterAction) return false;
    if (filterEnabled === "enabled" && !r.enabled) return false;
    if (filterEnabled === "disabled" && r.enabled) return false;
    return true;
  });

  const hostCodes = [...new Set(allRules.map((r) => r.host_code))].sort();

  const onToggleEnabled = (rule: CustomRule) => {
    toggleEnabled(
      {
        resource: "custom-rules",
        id: rule.id,
        values: { enabled: !rule.enabled },
        meta: { method: "patch" },
        successNotification: false,
      },
      {
        onSuccess: () => tableQuery.refetch(),
        onError: (err) => message.error(err.message),
      },
    );
  };

  const onDelete = (id: string) =>
    del(
      { resource: "custom-rules", id, successNotification: false },
      {
        onSuccess: () => {
          message.success(t("rules.saved"));
          tableQuery.refetch();
        },
        onError: (err) => message.error(err.message),
      },
    );

  const openCreate = () => setDrawerState({ open: true, mode: "create" });

  const openEdit = (rule: CustomRule) =>
    setDrawerState({ open: true, mode: "edit", initial: rule });

  const openDuplicate = (rule: CustomRule) => {
    // Strip id so it creates a new rule
    setDrawerState({
      open: true,
      mode: "create",
      initial: { ...rule, id: "", name: `${rule.name} (copy)` },
    });
  };

  const columns: ColumnsType<CustomRule> = [
    {
      title: t("common.name"),
      dataIndex: "name",
      render: (v: string) => <strong>{v}</strong>,
    },
    {
      title: t("rules.host"),
      dataIndex: "host_code",
      render: (v: string) => (
        <span style={{ fontFamily: "ui-monospace, monospace", color: "#8c8c8c" }}>{v}</span>
      ),
    },
    {
      title: t("rules.priority"),
      dataIndex: "priority",
      width: 90,
      sorter: (a, b) => a.priority - b.priority,
    },
    {
      title: t("security.action"),
      dataIndex: "action",
      width: 110,
      render: (v: string) => <Tag color={actionColor(v)}>{v}</Tag>,
    },
    {
      title: "Mode",
      key: "mode",
      width: 80,
      render: (_v, r) => conditionModeBadge(r),
    },
    {
      title: t("common.enabled"),
      dataIndex: "enabled",
      width: 90,
      render: (v: boolean, r) => (
        <Tooltip title={v ? t("rules.disable") : t("rules.enable")}>
          <Switch
            size="small"
            checked={v}
            onChange={() => onToggleEnabled(r)}
          />
        </Tooltip>
      ),
    },
    {
      title: t("common.actions"),
      key: "ops",
      width: 130,
      render: (_v, r) => (
        <Space size="small">
          <Tooltip title={t("common.edit")}>
            <Button
              type="text"
              size="small"
              icon={<EditOutlined />}
              onClick={() => openEdit(r)}
            />
          </Tooltip>
          <Tooltip title={t("rules.duplicate")}>
            <Button
              type="text"
              size="small"
              icon={<CopyOutlined />}
              onClick={() => openDuplicate(r)}
            />
          </Tooltip>
          <Popconfirm title={t("rules.confirmDelete")} onConfirm={() => onDelete(r.id)}>
            <Button type="text" danger size="small">
              {t("common.delete")}
            </Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <Typography.Title level={4} style={{ margin: 0 }}>
          {t("nav.customRules")}
        </Typography.Title>
        <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
          {t("rules.newRule")}
        </Button>
      </Space>

      <Card size="small">
        <Space wrap style={{ marginBottom: 12 }}>
          <Select
            allowClear
            placeholder={t("rules.host")}
            value={filterHostCode}
            onChange={setFilterHostCode}
            style={{ width: 160 }}
            options={hostCodes.map((h) => ({ value: h, label: h }))}
          />
          <Select
            allowClear
            placeholder={t("security.action")}
            value={filterAction}
            onChange={setFilterAction}
            style={{ width: 130 }}
            options={[
              { value: "block", label: "block" },
              { value: "allow", label: "allow" },
              { value: "log", label: "log" },
              { value: "challenge", label: "challenge" },
            ]}
          />
          <Select
            allowClear
            placeholder={t("rules.allStatus")}
            value={filterEnabled}
            onChange={setFilterEnabled}
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
          loading={tableQuery.isLoading}
          pagination={{ pageSize: 20, showSizeChanger: true }}
          locale={{ emptyText: t("rules.noCustomRules") }}
        />
      </Card>

      <CustomRuleEditorDrawer
        open={drawerState.open}
        mode={drawerState.open ? drawerState.mode : "create"}
        initial={drawerState.open ? drawerState.initial : undefined}
        onClose={() => setDrawerState({ open: false })}
        onSaved={() => {
          setDrawerState({ open: false });
          tableQuery.refetch();
        }}
      />
    </Space>
  );
};
