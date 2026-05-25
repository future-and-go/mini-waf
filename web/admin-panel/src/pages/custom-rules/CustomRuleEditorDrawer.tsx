import {
  Alert,
  App,
  Button,
  Drawer,
  Form,
  Input,
  InputNumber,
  Segmented,
  Select,
  Space,
  Switch,
  Typography,
} from "antd";
import { useCreate, useUpdate } from "@refinedev/core";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type {
  Condition,
  ConditionNode,
  ConditionOp,
  CreateCustomRulePayload,
  CustomRule,
  RuleAction,
} from "../../types/api";
import { ConditionTreeEditor } from "./ConditionTreeEditor";
import { isConditionNodeShape, validateTree } from "../../utils/conditionTree";

// ── Types ─────────────────────────────────────────────────────────────────────

interface MetaFields {
  name: string;
  host_code: string;
  description?: string;
  priority: number;
  action: RuleAction;
  action_status: number;
  action_msg?: string;
  enabled: boolean;
  condition_op: ConditionOp;
  script?: string;
}

type EditorMode = "visual" | "json";

export interface CustomRuleEditorDrawerProps {
  open: boolean;
  mode: "create" | "edit";
  initial?: CustomRule;
  onClose: () => void;
  onSaved: () => void;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function initialTree(rule?: CustomRule): ConditionNode | null {
  if (!rule) return null;
  // Backend normalises to top-level match_tree; handle both shapes defensively.
  if (rule.match_tree) return rule.match_tree;
  // Fallback: packed shape {"match_tree": ...} still inside conditions
  const cond = rule.conditions as unknown;
  if (cond && typeof cond === "object" && !Array.isArray(cond)) {
    const mt = (cond as Record<string, unknown>).match_tree;
    if (mt) return mt as ConditionNode;
  }
  // Legacy flat array
  if (Array.isArray(cond) && (cond as Condition[]).length > 0) {
    return { [rule.condition_op ?? "and"]: cond } as ConditionNode;
  }
  return null;
}

const ACTION_OPTIONS: { value: RuleAction; label: string }[] = [
  { value: "block", label: "block" },
  { value: "allow", label: "allow" },
  { value: "log", label: "log" },
  { value: "challenge", label: "challenge" },
];

// ── Component ─────────────────────────────────────────────────────────────────

export const CustomRuleEditorDrawer: React.FC<CustomRuleEditorDrawerProps> = ({
  open,
  mode,
  initial,
  onClose,
  onSaved,
}) => {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [form] = Form.useForm<MetaFields>();

  const [tree, setTree] = useState<ConditionNode | null>(null);
  const [editorMode, setEditorMode] = useState<EditorMode>("visual");
  const [jsonText, setJsonText] = useState("");
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [treeError, setTreeError] = useState<string | null>(null);
  const [switchWarning, setSwitchWarning] = useState<string | null>(null);

  const { mutate: create, mutation: createMutation } = useCreate();
  const { mutate: update, mutation: updateMutation } = useUpdate();
  const submitting = createMutation.isPending || updateMutation.isPending;

  // Populate form when drawer opens
  useEffect(() => {
    if (!open) return;
    setEditorMode("visual");
    setJsonText("");
    setJsonError(null);
    setTreeError(null);
    setSwitchWarning(null);

    if (initial) {
      form.setFieldsValue({
        name: initial.name,
        host_code: initial.host_code,
        description: initial.description ?? undefined,
        priority: initial.priority,
        action: initial.action,
        action_status: initial.action_status ?? 403,
        action_msg: initial.action_msg ?? undefined,
        enabled: initial.enabled,
        condition_op: initial.condition_op ?? "and",
        script: initial.script ?? undefined,
      });
      setTree(initialTree(initial));
    } else {
      form.resetFields();
      form.setFieldsValue({
        host_code: "*",
        priority: 100,
        action: "block",
        action_status: 403,
        enabled: true,
        condition_op: "and",
      });
      setTree(null);
    }
  }, [open, initial, form]);

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

  // ── Save ──────────────────────────────────────────────────────────────────

  const onSave = async () => {
    let meta: MetaFields;
    try {
      meta = await form.validateFields();
    } catch {
      return;
    }

    // Resolve the final tree value
    let resolvedTree: ConditionNode | null = null;

    if (editorMode === "visual") {
      if (tree !== null) {
        const vr = validateTree(tree);
        if (!vr.ok) {
          setTreeError(t(`rules.${vr.error}`, { max: vr.max }));
          return;
        }
        resolvedTree = tree;
      }
    } else {
      if (jsonText.trim()) {
        let parsed: unknown;
        try {
          parsed = JSON.parse(jsonText);
        } catch {
          setJsonError(t("rules.invalidJson"));
          return;
        }
        if (!isConditionNodeShape(parsed)) {
          setJsonError(t("rules.invalidJson"));
          return;
        }
        const vr = validateTree(parsed);
        if (!vr.ok) {
          setJsonError(t(`rules.${vr.error}`, { max: vr.max }));
          return;
        }
        resolvedTree = parsed;
      }
    }

    // Build payload
    const payload: CreateCustomRulePayload = {
      host_code: meta.host_code,
      name: meta.name,
      description: meta.description ?? null,
      priority: meta.priority,
      enabled: meta.enabled,
      action: meta.action,
      action_status: meta.action_status,
      action_msg: meta.action_msg ?? null,
    };

    if (meta.script?.trim()) {
      payload.script = meta.script;
      payload.conditions = [];
    } else if (resolvedTree) {
      payload.match_tree = resolvedTree;
      payload.conditions = [];
    } else {
      payload.condition_op = meta.condition_op;
      payload.conditions = [];
    }

    const opts = {
      onSuccess: () => {
        message.success(t("rules.saved"));
        onSaved();
      },
      onError: (err: { message: string }) => message.error(err.message),
    };

    if (mode === "edit" && initial?.id) {
      update(
        { resource: "custom-rules", id: initial.id, values: payload, successNotification: false },
        opts,
      );
    } else {
      create(
        { resource: "custom-rules", values: payload, successNotification: false },
        opts,
      );
    }
  };

  // ── Flat conditions from conditions[] (legacy preview) ────────────────────
  const flatConditions: Condition[] = initial?.conditions ?? [];

  const title =
    mode === "edit"
      ? `${t("common.edit")}: ${initial?.name ?? ""}`
      : t("rules.createRule");

  return (
    <Drawer
      title={title}
      placement="right"
      width={720}
      open={open}
      onClose={onClose}
      aria-label={title}
      extra={
        <Space>
          <Button onClick={onClose}>{t("common.cancel")}</Button>
          <Button type="primary" loading={submitting} onClick={() => void onSave()}>
            {t("common.save")}
          </Button>
        </Space>
      }
      destroyOnClose
    >
      <Form form={form} layout="vertical">
        {/* ── Metadata ─── */}
        <Space.Compact style={{ width: "100%" }}>
          <Form.Item
            name="name"
            label={t("common.name")}
            rules={[{ required: true, message: "Name is required" }]}
            style={{ flex: 2 }}
          >
            <Input />
          </Form.Item>
          <Form.Item name="host_code" label={t("rules.host")} style={{ flex: 1 }}>
            <Input placeholder="*" />
          </Form.Item>
        </Space.Compact>

        <Form.Item name="description" label={t("common.description")}>
          <Input.TextArea rows={2} />
        </Form.Item>

        <Space wrap style={{ width: "100%" }}>
          <Form.Item
            name="priority"
            label={t("rules.priority")}
            rules={[{ required: true, type: "integer", min: 0 }]}
            style={{ width: 120 }}
          >
            <InputNumber min={0} max={9999} style={{ width: "100%" }} />
          </Form.Item>
          <Form.Item
            name="action"
            label={t("security.action")}
            rules={[{ required: true }]}
            style={{ width: 130 }}
          >
            <Select options={ACTION_OPTIONS} />
          </Form.Item>
          <Form.Item name="action_status" label={t("rules.actionStatus")} style={{ width: 130 }}>
            <InputNumber min={100} max={599} style={{ width: "100%" }} />
          </Form.Item>
          <Form.Item name="enabled" label={t("common.enabled")} valuePropName="checked">
            <Switch />
          </Form.Item>
        </Space>

        <Form.Item name="action_msg" label={t("rules.actionMessage")}>
          <Input placeholder="Blocked by custom rule" />
        </Form.Item>

        {/* ── Condition builder ─── */}
        <Form.Item label={t("rules.visualEditor")}>
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
                onChange={(v) => { setTree(v); setTreeError(null); }}
                error={treeError ?? undefined}
              />
            ) : (
              <div>
                <Input.TextArea
                  rows={10}
                  value={jsonText}
                  onChange={(e) => { setJsonText(e.target.value); setJsonError(null); }}
                  style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}
                  placeholder='{ "and": [ { "field": "ip", "operator": "eq", "value": "1.2.3.4" } ] }'
                />
                {jsonError && (
                  <Typography.Text type="danger">{jsonError}</Typography.Text>
                )}
              </div>
            )}

            {/* Show flat conditions from legacy rules in read-only preview */}
            {mode === "edit" && flatConditions.length > 0 && !initial?.match_tree && (
              <Alert
                type="info"
                showIcon
                message={`${t("rules.flatMode")}: ${flatConditions.length} condition(s)`}
                description={
                  <Typography.Text type="secondary" style={{ fontSize: 11 }}>
                    {JSON.stringify(flatConditions)}
                  </Typography.Text>
                }
              />
            )}
          </Space>
        </Form.Item>

        {/* ── Rhai Script ─── */}
        <Form.Item name="script" label={t("rules.script")}>
          <Input.TextArea
            rows={5}
            placeholder={"// Rhai script\n// request.ip, request.path, request.method, request.headers"}
            style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}
          />
        </Form.Item>
      </Form>
    </Drawer>
  );
};
