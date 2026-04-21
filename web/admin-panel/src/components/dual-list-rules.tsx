import { useState } from "react";
import { Card, Input, Button, List, Space, Empty, Popconfirm } from "antd";
import { PlusOutlined, CloseOutlined } from "@ant-design/icons";
import { useTranslation } from "react-i18next";

// Loose row contract so concrete domain types (IpRule, UrlRule) can be
// passed in without an extra index-signature constraint at the call site.
type RuleRow = {
  id: string;
  host_code?: string;
} & Record<string, unknown>;

interface DualListRulesProps {
  title: string;
  color: "green" | "red";
  rows: ReadonlyArray<{ id: string; host_code?: string }>;
  fieldKey: string;
  fieldLabel: string;
  onAdd: (data: Record<string, unknown>) => Promise<void> | void;
  onDelete: (id: string) => Promise<void> | void;
  loading?: boolean;
}

// Reusable allow/block list panel. Used by IpRules + UrlRules.
// Hand-rolled rather than via Refine `useTable` because the list is small,
// the layout is symmetric (two side-by-side panels), and we want the
// inline-add UX of the original Vue component.
export const DualListRules: React.FC<DualListRulesProps> = ({
  title,
  color,
  rows,
  fieldKey,
  fieldLabel,
  onAdd,
  onDelete,
  loading,
}) => {
  const { t } = useTranslation();
  const [showAdd, setShowAdd] = useState(false);
  const [value, setValue] = useState("");
  const [hostCode, setHostCode] = useState("");

  const submit = async () => {
    if (!value) return;
    await onAdd({ [fieldKey]: value, host_code: hostCode || "*" });
    setValue("");
    setHostCode("");
    setShowAdd(false);
  };

  const titleColor = color === "green" ? "#389e0d" : "#cf1322";

  return (
    <Card
      size="small"
      title={<span style={{ color: titleColor, fontWeight: 600 }}>{title}</span>}
      extra={
        <Button type="link" size="small" icon={<PlusOutlined />} onClick={() => setShowAdd((s) => !s)}>
          {t("common.add")}
        </Button>
      }
      loading={loading}
    >
      {showAdd && (
        <Space.Compact style={{ width: "100%", marginBottom: 12 }}>
          <Input
            placeholder={fieldLabel}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            onPressEnter={submit}
          />
          <Input
            placeholder={t("security.hostCode")}
            value={hostCode}
            onChange={(e) => setHostCode(e.target.value)}
            style={{ width: 140 }}
            onPressEnter={submit}
          />
          <Button type="primary" onClick={submit}>
            {t("common.add")}
          </Button>
        </Space.Compact>
      )}

      {rows.length === 0 ? (
        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t("common.noData")} />
      ) : (
        <List
          size="small"
          dataSource={rows as RuleRow[]}
          renderItem={(row) => (
            <List.Item
              actions={[
                <Popconfirm
                  key="del"
                  title={t("common.confirm")}
                  onConfirm={() => onDelete(row.id)}
                >
                  <Button size="small" type="text" icon={<CloseOutlined />} danger />
                </Popconfirm>,
              ]}
            >
              <Space>
                <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>
                  {String(row[fieldKey] ?? "")}
                </span>
                <span style={{ color: "#bfbfbf", fontSize: 11 }}>{row.host_code}</span>
              </Space>
            </List.Item>
          )}
        />
      )}
    </Card>
  );
};
