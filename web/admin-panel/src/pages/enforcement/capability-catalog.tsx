import { useMemo, useRef, useState } from "react";
import { Card, Table, Segmented, Input, Space, Tag, Tooltip, Alert, Badge, App } from "antd";
import { WarningOutlined } from "@ant-design/icons";
import type { ColumnsType } from "antd/es/table";
import { useCustomMutation, useGo } from "@refinedev/core";
import { useTranslation } from "react-i18next";

import type {
  ActiveModes,
  CapabilityInfo,
  InteropMode,
  SetProfileBody,
  SetProfileResponse,
} from "../../types/api";
import { ENFORCEMENT_ROUTES } from "../../providers/enforcement-provider";
import { ModeTag } from "../../components/mode-tag";
import { governanceFor } from "../../utils/governance-map";

interface Props {
  features: Record<string, CapabilityInfo>;
  active: ActiveModes;
  onRefetch: () => void;
}

type QuickFilter = "all" | "enforce" | "log_only" | "overridden";
interface FeatureRow {
  key: string;
  feature: string;
  info: CapabilityInfo;
}

// The single known runtime gap called out in the spec: per-tier DDoS mode is
// accepted by the control plane but not yet honored by the detector.
const KNOWN_GAP = "ddos_protection.per_tier";

export const CapabilityCatalog: React.FC<Props> = ({ features, active, onRefetch }) => {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const go = useGo();
  const { mutate } = useCustomMutation<SetProfileResponse>();

  const [pendingKey, setPendingKey] = useState<string | null>(null);
  const [unsupported, setUnsupported] = useState<string[]>([]);
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<QuickFilter>("all");
  const debounce = useRef<ReturnType<typeof setTimeout>>();

  // policy override > feature override > default — mirrors mode_registry.rs.
  const effective = (feat: string, pol?: string): InteropMode => {
    const o = active.overrides;
    if (pol && o[`${feat}.${pol}`]) return o[`${feat}.${pol}`];
    if (o[feat]) return o[feat];
    return active.default_mode;
  };
  const isOverridden = (feat: string, pol?: string): boolean =>
    pol ? `${feat}.${pol}` in active.overrides : feat in active.overrides;

  const apply = (key: string, values: SetProfileBody) => {
    setPendingKey(key);
    mutate(
      { url: ENFORCEMENT_ROUTES.setProfile, method: "post", values },
      {
        onSuccess: (resp) => {
          setUnsupported(resp.data?.unsupported ?? []);
          message.success(t("enforcement.applied"));
          onRefetch();
        },
        onError: (err) => message.error(err.message),
        onSettled: () => setPendingKey(null),
      },
    );
  };

  const onSearch = (v: string) => {
    clearTimeout(debounce.current);
    debounce.current = setTimeout(() => setSearch(v.trim().toLowerCase()), 300);
  };

  const modeControl = (mode: InteropMode, key: string, toggleable: boolean, onChange: (m: InteropMode) => void) => (
    <Segmented<InteropMode>
      size="small"
      value={mode}
      disabled={!toggleable || pendingKey === key}
      onChange={onChange}
      options={[
        { value: "enforce", label: t("enforcement.modeEnforce") },
        { value: "log_only", label: t("enforcement.modeLogOnly") },
      ]}
    />
  );

  const rows: FeatureRow[] = useMemo(() => {
    const all = Object.entries(features).map(([feature, info]) => ({ key: feature, feature, info }));
    return all.filter(({ feature, info }) => {
      if (search) {
        const hit = feature.toLowerCase().includes(search) ||
          info.policies.some((p) => p.toLowerCase().includes(search));
        if (!hit) return false;
      }
      if (filter === "overridden") {
        return isOverridden(feature) || info.policies.some((p) => isOverridden(feature, p));
      }
      if (filter === "enforce" || filter === "log_only") return effective(feature) === filter;
      return true;
    });
    // active drives effective()/isOverridden(); re-filter when overrides change.
  }, [features, active, search, filter]);

  const policyColumns = (feature: string): ColumnsType<{ key: string; policy: string }> => [
    {
      title: t("enforcement.policyLabel"),
      dataIndex: "policy",
      render: (policy: string) => {
        const gap = `${feature}.${policy}` === KNOWN_GAP;
        return (
          <Space>
            <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>{policy}</span>
            {gap && (
              <Tooltip title={t("enforcement.perTierGap")}>
                <Tag color="warning" icon={<WarningOutlined />} style={{ marginInlineEnd: 0 }} />
              </Tooltip>
            )}
            {isOverridden(feature, policy) && <Tag>{t("enforcement.overridden")}</Tag>}
          </Space>
        );
      },
    },
    {
      title: t("enforcement.colEffectiveMode"),
      width: 140,
      render: (_, r) => <ModeTag mode={effective(feature, r.policy)} />,
    },
    {
      title: t("enforcement.colStatus"),
      width: 220,
      render: (_, r) => {
        const key = `${feature}.${r.policy}`;
        return modeControl(effective(feature, r.policy), key, true, (mode) =>
          apply(key, { scope: "policies", mode, feature, policies: [r.policy] }),
        );
      },
    },
  ];

  // Purely-informational plane dots (S6 mapping); the Admin dot deep-links out.
  const planeBadges = (feature: string) => {
    const gov = governanceFor(feature);
    if (!gov) return null;
    return (
      <Space size={4}>
        {gov.config && (
          <Tooltip title={t("enforcement.colConfigPlane")}><Badge color="geekblue" /></Tooltip>
        )}
        {gov.adminPath && (
          <Tooltip title={t("enforcement.colAdminPlane")}>
            <span style={{ cursor: "pointer" }} onClick={() => go({ to: gov.adminPath as string })}>
              <Badge color="cyan" />
            </span>
          </Tooltip>
        )}
        <Tooltip title={t("enforcement.colControlPlane")}><Badge color="green" /></Tooltip>
      </Space>
    );
  };

  const columns: ColumnsType<FeatureRow> = [
    {
      title: t("enforcement.colCapability"),
      dataIndex: "feature",
      render: (feature: string, row) => (
        <Space>
          <strong>{feature}</strong>
          {planeBadges(feature)}
          <Tag>{row.info.policies.length}</Tag>
          {isOverridden(feature) && <Tag color="blue">{t("enforcement.overridden")}</Tag>}
          {!row.info.toggleable && <Tag>{t("enforcement.notToggleable")}</Tag>}
        </Space>
      ),
    },
    {
      title: t("enforcement.colEffectiveMode"),
      width: 140,
      render: (_, row) => <ModeTag mode={effective(row.feature)} />,
    },
    {
      title: t("enforcement.colStatus"),
      width: 220,
      render: (_, row) =>
        modeControl(effective(row.feature), row.feature, row.info.toggleable, (mode) =>
          apply(row.feature, { scope: "features", mode, features: [row.feature] }),
        ),
    },
  ];

  return (
    <Card title={t("enforcement.catalogTitle")}>
      <Space direction="vertical" size="middle" style={{ width: "100%" }}>
        <Space wrap>
          <Input.Search
            allowClear
            placeholder={t("enforcement.searchPlaceholder")}
            onChange={(e) => onSearch(e.target.value)}
            onSearch={(v) => setSearch(v.trim().toLowerCase())}
            style={{ width: 280 }}
          />
          <Segmented<QuickFilter>
            value={filter}
            onChange={setFilter}
            options={[
              { value: "all", label: t("enforcement.filterAll") },
              { value: "enforce", label: t("enforcement.filterEnforce") },
              { value: "log_only", label: t("enforcement.filterLogOnly") },
              { value: "overridden", label: t("enforcement.filterOverridden") },
            ]}
          />
        </Space>

        {unsupported.length > 0 && (
          <Alert
            type="warning"
            showIcon
            closable
            onClose={() => setUnsupported([])}
            message={t("enforcement.unsupportedWarning", { list: unsupported.join(", ") })}
          />
        )}

        <Table<FeatureRow>
          rowKey="key"
          size="small"
          dataSource={rows}
          columns={columns}
          pagination={false}
          expandable={{
            expandedRowRender: (row) => (
              <Table
                rowKey="key"
                size="small"
                showHeader={false}
                pagination={false}
                dataSource={row.info.policies.map((p) => ({ key: `${row.feature}.${p}`, policy: p }))}
                columns={policyColumns(row.feature)}
              />
            ),
            rowExpandable: (row) => row.info.policies.length > 0,
          }}
        />
      </Space>
    </Card>
  );
};
