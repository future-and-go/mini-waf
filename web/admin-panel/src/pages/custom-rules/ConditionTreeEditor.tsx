import {
  Button,
  Input,
  InputNumber,
  Modal,
  Select,
  Space,
  Tag,
  Tooltip,
  Typography,
} from "antd";
import {
  DeleteOutlined,
  PlusOutlined,
} from "@ant-design/icons";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import type { Condition, ConditionField, ConditionNode, ConditionValue, RuleOperator } from "../../types/api";
import {
  compileFieldLabel,
  isAnd,
  isLeaf,
  isNot,
  parseFieldLabel,
} from "../../utils/conditionTree";

// ── Field catalog ─────────────────────────────────────────────────────────────

const SIMPLE_FIELDS = [
  { group: "Request", values: ["ip", "method", "path", "query", "body"] },
  { group: "Headers", values: ["host", "user_agent", "content_type", "content_length"] },
  { group: "Geo", values: ["geo_country", "geo_iso", "geo_province", "geo_city", "geo_isp"] },
];

const NUMERIC_FIELDS = new Set(["content_length"]);
const CIDR_FIELDS = new Set(["ip"]);

type FieldCategory = "simple" | "header" | "cookie";

function fieldCategory(f: ConditionField): FieldCategory {
  if (typeof f === "string") return "simple";
  if ("header" in f) return "header";
  return "cookie";
}

function availableOperators(f: ConditionField): RuleOperator[] {
  const label = typeof f === "string" ? f : "header" in f ? "header" : "cookie";
  if (NUMERIC_FIELDS.has(label)) {
    return ["eq", "ne", "gt", "lt", "gte", "lte"];
  }
  const ops: RuleOperator[] = [
    "eq", "ne", "contains", "not_contains",
    "starts_with", "ends_with",
    "regex", "wildcard",
    "in_list", "not_in_list",
  ];
  if (CIDR_FIELDS.has(label)) ops.push("cidr_match");
  return ops;
}

// ── Regex test modal ──────────────────────────────────────────────────────────

const RegexTestModal: React.FC<{ pattern: string; open: boolean; onClose: () => void }> = ({
  pattern,
  open,
  onClose,
}) => {
  const { t } = useTranslation();
  const [sample, setSample] = useState("");
  let matched: boolean | null = null;
  if (sample) {
    try {
      matched = new RegExp(pattern).test(sample);
    } catch {
      matched = null;
    }
  }
  return (
    <Modal title={t("rules.testRegex")} open={open} onCancel={onClose} footer={null} width={480}>
      <Space direction="vertical" style={{ width: "100%" }}>
        <Input
          placeholder={t("rules.regexSample")}
          value={sample}
          onChange={(e) => setSample(e.target.value)}
        />
        {sample && matched !== null && (
          <Tag color={matched ? "green" : "red"}>
            {matched ? t("rules.regexMatch") : t("rules.regexNoMatch")}
          </Tag>
        )}
      </Space>
    </Modal>
  );
};

// ── Leaf editor ───────────────────────────────────────────────────────────────

const LeafEditor: React.FC<{
  leaf: Condition;
  onChange: (updated: Condition) => void;
  onRemove: () => void;
}> = ({ leaf, onChange, onRemove }) => {
  const { t } = useTranslation();
  const [regexOpen, setRegexOpen] = useState(false);

  const cat = fieldCategory(leaf.field);
  const extraName =
    cat === "header"
      ? (leaf.field as { header: string }).header
      : cat === "cookie"
        ? ((leaf.field as { cookie: string | null }).cookie ?? "")
        : "";

  const ops = availableOperators(leaf.field);
  const currentOp = ops.includes(leaf.operator) ? leaf.operator : ops[0];

  const handleFieldType = (val: string) => {
    let newField: ConditionField;
    if (val === "header") {
      newField = { header: extraName || "x-custom" };
    } else if (val === "cookie") {
      newField = { cookie: extraName || null };
    } else {
      newField = val as ConditionField;
    }
    const newOps = availableOperators(newField);
    onChange({
      ...leaf,
      field: newField,
      operator: newOps.includes(leaf.operator) ? leaf.operator : newOps[0],
    });
  };

  const handleExtraName = (val: string) => {
    if (cat === "header") {
      onChange({ ...leaf, field: { header: val } });
    } else if (cat === "cookie") {
      onChange({ ...leaf, field: { cookie: val || null } });
    }
  };

  const handleOperator = (op: RuleOperator) => {
    let newValue: ConditionValue = leaf.value;
    if ((op === "in_list" || op === "not_in_list") && !Array.isArray(newValue)) {
      newValue = newValue !== "" ? [String(newValue)] : [];
    } else if ((op === "gt" || op === "lt" || op === "gte" || op === "lte") && typeof newValue !== "number") {
      newValue = Number(newValue) || 0;
    } else if (op !== "in_list" && op !== "not_in_list" && Array.isArray(newValue)) {
      newValue = newValue.join(",");
    }
    onChange({ ...leaf, operator: op, value: newValue });
  };

  const handleValue = (v: ConditionValue) => onChange({ ...leaf, value: v });

  const fieldTypeValue = cat === "simple" ? (leaf.field as string) : cat;

  const fieldOptions = [
    ...SIMPLE_FIELDS.map(({ group, values }) => ({
      label: group,
      options: values.map((v) => ({ value: v, label: v })),
    })),
    {
      label: "Custom",
      options: [
        { value: "header", label: "header.*" },
        { value: "cookie", label: "cookie.*" },
      ],
    },
  ];

  return (
    <div
      style={{
        display: "flex",
        flexWrap: "wrap",
        gap: 6,
        alignItems: "center",
        background: "#fafafa",
        border: "1px solid #e8e8e8",
        borderRadius: 6,
        padding: "6px 10px",
        marginBottom: 4,
      }}
    >
      <Select
        value={fieldTypeValue}
        onChange={handleFieldType}
        options={fieldOptions}
        style={{ minWidth: 140 }}
        size="small"
      />
      {(cat === "header" || cat === "cookie") && (
        <Input
          size="small"
          value={extraName}
          onChange={(e) => handleExtraName(e.target.value)}
          placeholder={cat === "header" ? t("rules.fieldHeader") : t("rules.fieldCookie")}
          style={{ width: 130 }}
        />
      )}
      <Select
        value={currentOp}
        onChange={handleOperator}
        options={ops.map((o) => ({ value: o, label: o }))}
        style={{ minWidth: 120 }}
        size="small"
      />
      {(currentOp === "in_list" || currentOp === "not_in_list") ? (
        <Select
          mode="tags"
          size="small"
          value={Array.isArray(leaf.value) ? leaf.value : leaf.value !== "" ? [String(leaf.value)] : []}
          onChange={(v: string[]) => handleValue(v)}
          style={{ minWidth: 180 }}
          tokenSeparators={[","]}
          placeholder="value1,value2"
        />
      ) : currentOp === "gt" || currentOp === "lt" || currentOp === "gte" || currentOp === "lte" ? (
        <InputNumber
          size="small"
          value={typeof leaf.value === "number" ? leaf.value : Number(leaf.value) || 0}
          onChange={(v) => handleValue(v ?? 0)}
          style={{ width: 100 }}
        />
      ) : (
        <Input
          size="small"
          value={Array.isArray(leaf.value) ? leaf.value.join(",") : String(leaf.value)}
          onChange={(e) => handleValue(e.target.value)}
          style={{ minWidth: 160 }}
          placeholder={
            currentOp === "cidr_match"
              ? "10.0.0.0/8 or 2001:db8::/32"
              : currentOp === "wildcard"
                ? "* = segment, ** = cross-segment"
                : "value"
          }
        />
      )}
      {currentOp === "regex" && (
        <>
          <Button size="small" onClick={() => setRegexOpen(true)}>
            {t("rules.testRegex")}
          </Button>
          <RegexTestModal
            pattern={Array.isArray(leaf.value) ? leaf.value.join("") : String(leaf.value)}
            open={regexOpen}
            onClose={() => setRegexOpen(false)}
          />
        </>
      )}
      <Tooltip title={t("rules.removeNode")}>
        <Button size="small" type="text" danger icon={<DeleteOutlined />} onClick={onRemove} />
      </Tooltip>
    </div>
  );
};

// ── Recursive tree node ───────────────────────────────────────────────────────

interface NodeEditorProps {
  node: ConditionNode;
  onChange: (updated: ConditionNode) => void;
  onRemove: () => void;
  depth: number;
}

const NodeEditor: React.FC<NodeEditorProps> = ({ node, onChange, onRemove, depth }) => {
  const { t } = useTranslation();

  if (isLeaf(node)) {
    return <LeafEditor leaf={node} onChange={onChange} onRemove={onRemove} />;
  }

  if (isNot(node)) {
    return (
      <div
        style={{
          borderLeft: "3px solid #fa8c16",
          paddingLeft: 10,
          marginBottom: 4,
        }}
      >
        <Space style={{ marginBottom: 4 }}>
          <Tag color="orange">NOT</Tag>
          <Tooltip title={t("rules.removeNode")}>
            <Button size="small" type="text" danger icon={<DeleteOutlined />} onClick={onRemove} />
          </Tooltip>
        </Space>
        <NodeEditor
          node={node.not}
          onChange={(updated) => onChange({ not: updated })}
          onRemove={() => onChange(node.not)}
          depth={depth + 1}
        />
      </div>
    );
  }

  const isAndGroup = isAnd(node);
  const children: ConditionNode[] = isAndGroup
    ? (node as { and: ConditionNode[] }).and
    : (node as { or: ConditionNode[] }).or;

  const mkGroup = (newChildren: ConditionNode[]): ConditionNode =>
    isAndGroup ? { and: newChildren } : { or: newChildren };

  const updateChild = (idx: number, updated: ConditionNode) => {
    const next = [...children];
    next[idx] = updated;
    onChange(mkGroup(next));
  };

  const removeChild = (idx: number) => {
    onChange(mkGroup(children.filter((_, i) => i !== idx)));
  };

  const addLeaf = () => {
    const leaf: Condition = { field: "ip", operator: "eq", value: "" };
    onChange(mkGroup([...children, leaf]));
  };

  const addGroup = (type: "and" | "or") => {
    onChange(mkGroup([...children, type === "and" ? { and: [] } : { or: [] }]));
  };

  const wrapNot = () => onChange({ not: node });

  const borderColor = isAndGroup ? "#1677ff" : "#52c41a";
  const labelColor = isAndGroup ? "blue" : "green";
  const label = isAndGroup ? "AND" : "OR";

  return (
    <div
      style={{
        borderLeft: `3px solid ${borderColor}`,
        paddingLeft: 10,
        marginBottom: 6,
        background: depth % 2 === 0 ? "transparent" : "#fafafa",
      }}
    >
      <Space size="small" style={{ marginBottom: 4 }}>
        <Tag color={labelColor}>{label}</Tag>
        <Tooltip title={t("rules.addCondition")}>
          <Button size="small" icon={<PlusOutlined />} onClick={addLeaf}>
            {t("rules.addCondition")}
          </Button>
        </Tooltip>
        <Button size="small" onClick={() => addGroup("and")}>
          {t("rules.addAndGroup")}
        </Button>
        <Button size="small" onClick={() => addGroup("or")}>
          {t("rules.addOrGroup")}
        </Button>
        <Button size="small" onClick={wrapNot}>
          {t("rules.wrapNot")}
        </Button>
        <Tooltip title={t("rules.removeNode")}>
          <Button size="small" type="text" danger icon={<DeleteOutlined />} onClick={onRemove} />
        </Tooltip>
      </Space>
      {children.length === 0 && (
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          (empty group)
        </Typography.Text>
      )}
      {children.map((child, idx) => (
        <NodeEditor
          key={idx}
          node={child}
          onChange={(u) => updateChild(idx, u)}
          onRemove={() => removeChild(idx)}
          depth={depth + 1}
        />
      ))}
    </div>
  );
};

// ── Public component ──────────────────────────────────────────────────────────

interface ConditionTreeEditorProps {
  value: ConditionNode | null;
  onChange: (v: ConditionNode | null) => void;
  error?: string;
}

export const ConditionTreeEditor: React.FC<ConditionTreeEditorProps> = ({ value, onChange, error }) => {
  const { t } = useTranslation();

  if (value === null) {
    return (
      <Space>
        <Button onClick={() => onChange({ and: [] })} icon={<PlusOutlined />}>
          {t("rules.addAndGroup")}
        </Button>
        <Button onClick={() => onChange({ or: [] })} icon={<PlusOutlined />}>
          {t("rules.addOrGroup")}
        </Button>
      </Space>
    );
  }

  return (
    <div>
      {error && (
        <Typography.Text type="danger" style={{ display: "block", marginBottom: 8 }}>
          {error}
        </Typography.Text>
      )}
      <NodeEditor
        node={value}
        onChange={onChange}
        onRemove={() => onChange(null)}
        depth={0}
      />
    </div>
  );
};

// Exported for external parsing of field labels
export { compileFieldLabel, parseFieldLabel };
