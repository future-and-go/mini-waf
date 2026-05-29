import { Table, Tag, Popconfirm, Button, Drawer, Form, InputNumber, Select, Input } from "antd";
import { DeleteOutlined } from "@ant-design/icons";
import type { ColumnsType } from "antd/es/table";
import type { TFunction } from "i18next";
import {
  HTTP_METHODS,
  TIER_COLOR,
  TIER_KEYS,
  type ClassifierRule,
  type TierKey,
} from "../types";

interface ClassifierRulesTableProps {
  rules: ClassifierRule[];
  onDelete: (id: number) => void;
  disabled: boolean;
  t: TFunction;
  tierLabels: Record<TierKey, string>;
}

export const ClassifierRulesTable: React.FC<ClassifierRulesTableProps> = ({
  rules,
  onDelete,
  disabled,
  t,
  tierLabels,
}) => {
  const columns: ColumnsType<ClassifierRule> = [
    {
      title: t("tierPolicies.priority"),
      dataIndex: "priority",
      width: 80,
      sorter: (a, b) => a.priority - b.priority,
    },
    {
      title: t("tierPolicies.tier"),
      dataIndex: "tier",
      width: 100,
      render: (v: string) => {
        const color = TIER_COLOR[v as TierKey] ?? "default";
        return <Tag color={color}>{tierLabels[v as TierKey] ?? v}</Tag>;
      },
    },
    {
      title: t("tierPolicies.hostMatch"),
      dataIndex: "host_match",
      ellipsis: true,
      render: (v?: string) =>
        v ? (
          <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>{v}</span>
        ) : (
          <span style={{ color: "#bfbfbf" }}>*</span>
        ),
    },
    {
      title: t("tierPolicies.pathMatch"),
      dataIndex: "path_match",
      ellipsis: true,
      render: (v?: string) =>
        v ? (
          <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>{v}</span>
        ) : (
          <span style={{ color: "#bfbfbf" }}>*</span>
        ),
    },
    {
      title: t("tierPolicies.methods"),
      dataIndex: "methods",
      width: 180,
      render: (v?: string[]) =>
        v?.length ? (
          v.map((m) => (
            <Tag key={m} style={{ fontSize: 11 }}>
              {m}
            </Tag>
          ))
        ) : (
          <span style={{ color: "#bfbfbf" }}>{t("tierPolicies.allMethods")}</span>
        ),
    },
    {
      title: "",
      key: "actions",
      width: 60,
      render: (_: unknown, r: ClassifierRule) => (
        <Popconfirm
          title={t("common.confirm")}
          onConfirm={() => onDelete(r.id)}
          disabled={disabled}
        >
          <Button size="small" type="text" icon={<DeleteOutlined />} danger disabled={disabled} />
        </Popconfirm>
      ),
    },
  ];

  return (
    <Table<ClassifierRule>
      rowKey="id"
      size="small"
      dataSource={rules}
      columns={columns}
      pagination={false}
      locale={{ emptyText: t("tierPolicies.noRules") }}
      scroll={{ x: 700 }}
    />
  );
};

interface RuleDrawerProps {
  open: boolean;
  onClose: () => void;
  onAdd: () => void;
  form: ReturnType<typeof Form.useForm<Omit<ClassifierRule, "id">>>[0];
  t: TFunction;
  tierLabels: Record<TierKey, string>;
}

export const ClassifierRuleDrawer: React.FC<RuleDrawerProps> = ({
  open,
  onClose,
  onAdd,
  form,
  t,
  tierLabels,
}) => (
  <Drawer
    title={t("tierPolicies.addRuleTitle")}
    open={open}
    onClose={onClose}
    width={480}
    extra={
      <Button type="primary" onClick={onAdd}>
        {t("common.add")}
      </Button>
    }
    destroyOnClose
  >
    <Form form={form} layout="vertical" initialValues={{ priority: 100, tier: "medium" }}>
      <Form.Item name="priority" label={t("tierPolicies.priority")} rules={[{ required: true }]}>
        <InputNumber min={1} max={9999} style={{ width: "100%" }} />
      </Form.Item>
      <Form.Item name="tier" label={t("tierPolicies.tier")} rules={[{ required: true }]}>
        <Select options={TIER_KEYS.map((k) => ({ value: k, label: tierLabels[k] }))} />
      </Form.Item>
      <Form.Item name="host_match" label={t("tierPolicies.hostMatch")}>
        <Input placeholder="example.com" style={{ fontFamily: "ui-monospace, monospace" }} />
      </Form.Item>
      <Form.Item name="path_match" label={t("tierPolicies.pathMatch")}>
        <Input placeholder="/api/*" style={{ fontFamily: "ui-monospace, monospace" }} />
      </Form.Item>
      <Form.Item name="methods" label={t("tierPolicies.methods")}>
        <Select
          mode="multiple"
          options={HTTP_METHODS.map((m) => ({ value: m, label: m }))}
          placeholder={t("tierPolicies.allMethods")}
        />
      </Form.Item>
    </Form>
  </Drawer>
);
