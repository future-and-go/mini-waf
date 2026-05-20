import { useState, useEffect } from "react";
import {
  Modal,
  Steps,
  Form,
  Input,
  InputNumber,
  Select,
  Switch,
  Button,
  Space,
  Typography,
  Alert,
  Table,
  Segmented,
  Divider,
  Tag,
  App,
} from "antd";
import { useCreate, useUpdate, useCustom } from "@refinedev/core";
import { useTranslation } from "react-i18next";
import type { ColumnsType } from "antd/es/table";
import type {
  SecurityEvent,
  CreateCustomRulePayload,
  ConditionNode,
  RuleAction,
  Condition,
} from "../../types/api";
import { ConditionTreeEditor } from "../custom-rules/ConditionTreeEditor";
import { isConditionNodeShape, validateTree } from "../../utils/conditionTree";
import { fmtDateTime } from "../../utils/format";

// ── Props ─────────────────────────────────────────────────────────────────────

interface Props {
  open: boolean;
  event: SecurityEvent | null;
  onClose: () => void;
  onCreated: (ruleId: string) => void;
}

// ── Local types ───────────────────────────────────────────────────────────────

type EditorMode = "visual" | "json";

interface RuleFormFields {
  name: string;
  host_code: string;
  description?: string;
  priority: number;
  action: RuleAction;
  action_status: number;
  action_msg?: string;
  enabled: boolean;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function generateRhaiScript(event: SecurityEvent): string {
  const parts: string[] = [];
  parts.push(`ip == "${event.client_ip}"`);

  if (event.method && event.method !== "*") {
    parts.push(`method == "${event.method}"`);
  }

  if (event.path && event.path !== "/") {
    if (event.path.includes(".")) {
      parts.push(`path == "${event.path}"`);
    } else {
      parts.push(`path.starts_with("${event.path}")`);
    }
  }

  if (event.rule_name === "SSRF") {
    parts.push(`referer.contains("localhost") || referer.contains("127.0.0.1")`);
  }

  return parts.join(" && ");
}

function generateInitialTree(event: SecurityEvent): ConditionNode {
  const conditions: Condition[] = [
    { field: "ip", operator: "eq", value: event.client_ip },
  ];

  if (event.method && event.method !== "*") {
    conditions.push({ field: "method", operator: "eq", value: event.method });
  }

  if (event.path && event.path !== "/") {
    conditions.push({
      field: "path",
      operator: event.path.includes(".") ? "eq" : "starts_with",
      value: event.path,
    });
  }

  return { and: conditions } as ConditionNode;
}

function matchesRule(ev: SecurityEvent, source: SecurityEvent): boolean {
  if (ev.client_ip !== source.client_ip) return false;
  if (source.path && source.path !== "/") {
    if (source.path.includes(".")) return ev.path === source.path;
    return ev.path.startsWith(source.path);
  }
  return true;
}

function methodColor(method: string): string {
  const map: Record<string, string> = {
    GET: "blue",
    POST: "green",
    PUT: "orange",
    DELETE: "red",
    PATCH: "purple",
  };
  return map[method?.toUpperCase()] ?? "default";
}

function actionColor(action: string): string {
  if (action === "block") return "red";
  if (action === "allow") return "green";
  return "default";
}

const ACTION_OPTIONS: { value: RuleAction; label: string }[] = [
  { value: "block", label: "block" },
  { value: "allow", label: "allow" },
  { value: "log", label: "log" },
  { value: "challenge", label: "challenge" },
];

// ── Component ─────────────────────────────────────────────────────────────────

export const CreateRuleFromEventModal: React.FC<Props> = ({
  open,
  event,
  onClose,
  onCreated,
}) => {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [form] = Form.useForm<RuleFormFields>();

  const [step, setStep] = useState(0);
  const [tree, setTree] = useState<ConditionNode | null>(null);
  const [editorMode, setEditorMode] = useState<EditorMode>("visual");
  const [jsonText, setJsonText] = useState("");
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [treeError, setTreeError] = useState<string | null>(null);
  const [switchWarning, setSwitchWarning] = useState<string | null>(null);
  const [script, setScript] = useState("");
  const [createdRuleId, setCreatedRuleId] = useState<string | null>(null);

  const { mutate: create, mutation: createMutation } = useCreate();
  const { mutate: update, mutation: updateMutation } = useUpdate();
  const submitting = createMutation.isPending || updateMutation.isPending;

  // ── Reset when modal opens with a new event ───────────────────────────────

  useEffect(() => {
    if (!open || !event) return;
    setStep(0);
    setEditorMode("visual");
    setJsonText("");
    setJsonError(null);
    setTreeError(null);
    setSwitchWarning(null);
    setCreatedRuleId(null);
    setScript(generateRhaiScript(event));
    setTree(generateInitialTree(event));
    form.setFieldsValue({
      name: `Block ${event.rule_name} from ${event.client_ip}`,
      host_code: event.host_code,
      description: `Auto-generated from security event ${event.id} detected at ${event.created_at}`,
      priority: 1,
      action: "block",
      action_status: 403,
      action_msg: "Blocked by custom rule",
      enabled: false,
    });
  }, [open, event, form]);

  // ── Preview query (enabled only on step 2) ────────────────────────────────

  const previewQuery = useCustom<{ data: SecurityEvent[] }>({
    url: "/api/security-events",
    method: "get",
    config: {
      query: {
        client_ip: event?.client_ip,
        page_size: 1000,
        page: 1,
      },
    },
    queryOptions: {
      enabled: step === 1 && !!event?.client_ip,
      staleTime: 30_000,
      queryKey: ["preview-events", event?.client_ip, event?.path],
    },
  });

  const allPreviewEvents: SecurityEvent[] = (() => {
    const raw = previewQuery.result?.data;
    if (Array.isArray(raw)) return raw as SecurityEvent[];
    const nested = (raw as unknown as { data: SecurityEvent[] } | undefined)?.data;
    return Array.isArray(nested) ? nested : [];
  })();

  const matchedEvents = event
    ? allPreviewEvents.filter((ev) => matchesRule(ev, event))
    : [];

  // ── Editor mode switch ────────────────────────────────────────────────────

  const handleSwitchMode = (next: EditorMode) => {
    setSwitchWarning(null);
    if (next === "json") {
      setJsonText(tree ? JSON.stringify(tree, null, 2) : "");
      setJsonError(null);
    } else {
      if (jsonText.trim()) {
        try {
          const parsed = JSON.parse(jsonText) as unknown;
          if (!isConditionNodeShape(parsed)) {
            setSwitchWarning(t("rules.invalidJson"));
            return;
          }
          setTree(parsed);
        } catch {
          setSwitchWarning(t("rules.invalidJson"));
          return;
        }
      }
      setJsonError(null);
    }
    setEditorMode(next);
  };

  // ── Build payload from form + editor state ────────────────────────────────

  const buildPayload = (
    meta: RuleFormFields,
    resolvedTree: ConditionNode | null,
  ): CreateCustomRulePayload => {
    const payload: CreateCustomRulePayload = {
      host_code: meta.host_code,
      name: meta.name,
      description: meta.description ?? null,
      priority: meta.priority,
      enabled: false,
      action: meta.action,
      action_status: meta.action_status,
      action_msg: meta.action_msg ?? null,
    };

    if (script.trim()) {
      payload.script = script;
      payload.conditions = [];
    } else if (resolvedTree) {
      payload.match_tree = resolvedTree;
      payload.conditions = [];
    } else {
      payload.condition_op = "and";
      payload.conditions = [];
    }

    return payload;
  };

  // ── Resolve condition tree from current editor state ──────────────────────

  const resolveTree = (): { tree: ConditionNode | null; error: boolean } => {
    if (editorMode === "visual") {
      if (tree !== null) {
        const vr = validateTree(tree);
        if (!vr.ok) {
          setTreeError(t(`rules.${vr.error}`, { max: vr.max }));
          return { tree: null, error: true };
        }
      }
      return { tree, error: false };
    }

    if (jsonText.trim()) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(jsonText);
      } catch {
        setJsonError(t("rules.invalidJson"));
        return { tree: null, error: true };
      }
      if (!isConditionNodeShape(parsed)) {
        setJsonError(t("rules.invalidJson"));
        return { tree: null, error: true };
      }
      const vr = validateTree(parsed);
      if (!vr.ok) {
        setJsonError(t(`rules.${vr.error}`, { max: vr.max }));
        return { tree: null, error: true };
      }
      return { tree: parsed, error: false };
    }

    return { tree: null, error: false };
  };

  // ── Save as draft (POST or PATCH if already created) ─────────────────────

  const handleSaveDraft = async () => {
    let meta: RuleFormFields;
    try {
      meta = await form.validateFields();
    } catch {
      return;
    }

    const { tree: resolvedTree, error } = resolveTree();
    if (error) return;

    const payload = buildPayload(meta, resolvedTree);

    if (createdRuleId) {
      update(
        {
          resource: "custom-rules",
          id: createdRuleId,
          values: payload,
          successNotification: false,
        },
        {
          onSuccess: () => setStep(1),
          onError: (err) => {
            message.error(err.message ?? "Failed to update rule");
          },
        },
      );
    } else {
      create(
        { resource: "custom-rules", values: payload, successNotification: false },
        {
          onSuccess: (response) => {
            const ruleId = (
              response as unknown as { data?: { id?: string } }
            ).data?.id;
            if (ruleId) {
              setCreatedRuleId(ruleId);
              setStep(1);
            }
          },
          onError: (err) => {
            message.error(err.message ?? "Failed to create rule");
          },
        },
      );
    }
  };

  // ── Enable rule (PATCH enabled: true) ─────────────────────────────────────

  const handleEnableRule = () => {
    if (!createdRuleId) return;
    update(
      {
        resource: "custom-rules",
        id: createdRuleId,
        values: { enabled: true },
        successNotification: false,
      },
      {
        onSuccess: () => {
          onCreated(createdRuleId);
        },
        onError: (err) => {
          message.error(err.message ?? "Failed to enable rule");
        },
      },
    );
  };

  // ── Preview table columns ─────────────────────────────────────────────────

  const previewColumns: ColumnsType<SecurityEvent> = [
    {
      title: t("security.time"),
      dataIndex: "created_at",
      width: 155,
      render: (v: string) => (
        <span style={{ color: "#8c8c8c", fontSize: 12 }}>{fmtDateTime(v)}</span>
      ),
    },
    {
      title: t("security.clientIP"),
      dataIndex: "client_ip",
      width: 130,
      render: (v: string) => (
        <Typography.Text code style={{ fontSize: 11 }}>
          {v}
        </Typography.Text>
      ),
    },
    {
      title: t("security.method"),
      dataIndex: "method",
      width: 75,
      render: (v: string) => <Tag color={methodColor(v)}>{v}</Tag>,
    },
    {
      title: t("security.path"),
      dataIndex: "path",
      ellipsis: true,
      render: (v: string) => (
        <span
          style={{ fontFamily: "ui-monospace, monospace", fontSize: 11 }}
          title={v}
        >
          {v}
        </span>
      ),
    },
    {
      title: t("security.ruleName"),
      dataIndex: "rule_name",
      width: 145,
      ellipsis: true,
    },
    {
      title: t("security.action"),
      dataIndex: "action",
      width: 80,
      render: (v: string) => <Tag color={actionColor(v)}>{v}</Tag>,
    },
  ];

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <Modal
      open={open}
      onCancel={onClose}
      title={t("security.createRuleTitle")}
      width={900}
      footer={null}
      destroyOnClose
    >
      <Steps
        current={step}
        size="small"
        style={{ marginBottom: 24 }}
        items={[
          { title: t("rules.createRule") },
          { title: "Event Log Preview" },
        ]}
      />

      {/* ── Step 1: Review & Edit Rule ────────────────────────────────────── */}
      {step === 0 && (
        <Space direction="vertical" size="middle" style={{ width: "100%" }}>
          <Form form={form} layout="vertical">
            <Space.Compact style={{ width: "100%" }}>
              <Form.Item
                name="name"
                label={t("common.name")}
                rules={[{ required: true, message: "Name is required" }]}
                style={{ flex: 2, marginBottom: 0 }}
              >
                <Input />
              </Form.Item>
              <Form.Item
                name="host_code"
                label={t("rules.host")}
                style={{ flex: 1, marginBottom: 0 }}
              >
                <Input placeholder="*" />
              </Form.Item>
            </Space.Compact>

            <Form.Item
              name="description"
              label={t("common.description")}
              style={{ marginTop: 12 }}
            >
              <Input.TextArea rows={2} />
            </Form.Item>

            <Space wrap>
              <Form.Item
                name="priority"
                label={t("rules.priority")}
                rules={[{ required: true, type: "integer", min: 1 }]}
                style={{ width: 120 }}
                extra={
                  <span style={{ fontSize: 11 }}>
                    {t("security.priorityNote")}
                  </span>
                }
              >
                <InputNumber min={1} max={9999} style={{ width: "100%" }} />
              </Form.Item>
              <Form.Item
                name="action"
                label={t("security.action")}
                rules={[{ required: true }]}
                style={{ width: 130 }}
              >
                <Select options={ACTION_OPTIONS} />
              </Form.Item>
              <Form.Item
                name="action_status"
                label={t("rules.actionStatus")}
                style={{ width: 130 }}
              >
                <InputNumber min={100} max={599} style={{ width: "100%" }} />
              </Form.Item>
              <Form.Item
                name="action_msg"
                label={t("rules.actionMessage")}
                style={{ width: 220 }}
              >
                <Input />
              </Form.Item>
              <Form.Item
                name="enabled"
                label={t("common.enabled")}
                valuePropName="checked"
              >
                <Switch disabled />
              </Form.Item>
            </Space>

            {/* ── Condition builder ── */}
            <Form.Item label={t("rules.visualEditor")} style={{ marginBottom: 0 }}>
              <Space direction="vertical" style={{ width: "100%" }}>
                <Space>
                  <Segmented
                    value={editorMode}
                    onChange={(v) => handleSwitchMode(v as EditorMode)}
                    options={[
                      { label: t("rules.visualEditor"), value: "visual" },
                      { label: t("rules.jsonEditor"), value: "json" },
                    ]}
                  />
                  {switchWarning && (
                    <Typography.Text type="warning">{switchWarning}</Typography.Text>
                  )}
                </Space>

                {editorMode === "visual" ? (
                  <ConditionTreeEditor
                    value={tree}
                    onChange={(v) => {
                      setTree(v);
                      setTreeError(null);
                    }}
                    error={treeError ?? undefined}
                  />
                ) : (
                  <div>
                    <Input.TextArea
                      rows={8}
                      value={jsonText}
                      onChange={(e) => {
                        setJsonText(e.target.value);
                        setJsonError(null);
                      }}
                      style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}
                      placeholder='{ "and": [ { "field": "ip", "operator": "eq", "value": "1.2.3.4" } ] }'
                    />
                    {jsonError && (
                      <Typography.Text type="danger">{jsonError}</Typography.Text>
                    )}
                  </div>
                )}
              </Space>
            </Form.Item>

            {/* ── Rhai Script ── */}
            <Form.Item label={t("rules.script")} style={{ marginTop: 12 }}>
              <Input.TextArea
                rows={4}
                value={script}
                onChange={(e) => setScript(e.target.value)}
                style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}
              />
              <Typography.Text type="secondary" style={{ fontSize: 11 }}>
                {t("security.rhaiAutoGenNote")}
              </Typography.Text>
            </Form.Item>
          </Form>

          <Divider style={{ margin: "8px 0" }} />

          <div style={{ textAlign: "right" }}>
            <Space>
              <Button onClick={onClose}>{t("common.cancel")}</Button>
              <Button
                type="primary"
                loading={submitting}
                onClick={() => void handleSaveDraft()}
              >
                {t("security.saveAndPreview")} →
              </Button>
            </Space>
          </div>
        </Space>
      )}

      {/* ── Step 2: Event Log Preview ─────────────────────────────────────── */}
      {step === 1 && (
        <Space direction="vertical" size="middle" style={{ width: "100%" }}>
          <Alert
            type="warning"
            showIcon
            message={t("security.previewMode")}
            description={t("security.previewWarning")}
          />

          <Typography.Text type="secondary">
            {t("security.foundMatches", { count: matchedEvents.length })}
          </Typography.Text>

          <Table
            rowKey="id"
            size="small"
            dataSource={matchedEvents}
            columns={previewColumns}
            loading={previewQuery.query.isLoading}
            pagination={{ pageSize: 10, showSizeChanger: false }}
            scroll={{ x: 700 }}
            locale={{ emptyText: t("security.noEvents") }}
          />

          <Divider style={{ margin: "8px 0" }} />

          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <Button onClick={() => setStep(0)}>
              ← {t("security.backToEdit")}
            </Button>
            <Button
              type="primary"
              danger={matchedEvents.length === 0}
              style={
                matchedEvents.length > 0
                  ? { background: "#52c41a", borderColor: "#52c41a" }
                  : undefined
              }
              loading={updateMutation.isPending}
              onClick={handleEnableRule}
            >
              {t("security.enableRule")}
            </Button>
          </div>
        </Space>
      )}
    </Modal>
  );
};
