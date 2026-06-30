import { useState } from "react";
import { Card, Space, Select, Input, Button, Tooltip, Typography } from "antd";
import { ReloadOutlined } from "@ant-design/icons";

// ─── Public types ─────────────────────────────────────────────────────────────

export interface LogsFilterState {
  /** Enforcement action — maps to the `action` query param. */
  eventType?: string;
  ruleName?: string;
  clientIp?: string;
  hostCode?: string;
  path?: string;
}

// Defaults: no filters. The feed is server-paginated, newest first.
export const defaultLogsFilters = (): LogsFilterState => ({});

// ─── Component ────────────────────────────────────────────────────────────────

interface Props {
  value: LogsFilterState;
  onChange: (next: LogsFilterState) => void;
  onApply: () => void;
  loading: boolean;
}

/**
 * Sidebar filter panel for the logs viewer. Holds local state for free-text
 * inputs (so they don't fire a query on every keystroke) and bubbles a
 * coalesced `LogsFilterState` up via `onChange` only when the user clicks
 * Apply.
 *
 * Filters map 1:1 onto `SecurityEventQuery` fields served by
 * `/api/security-events`. Fields the endpoint does not support (time range,
 * tier, free-text) are intentionally absent — see the A1 rewire plan.
 */
export const LogsFilters: React.FC<Props> = ({ value, onChange, onApply, loading }) => {
  // Local mirrors so typing in the text inputs doesn't cascade a query.
  const [ruleName, setRuleName] = useState(value.ruleName ?? "");
  const [clientIp, setClientIp] = useState(value.clientIp ?? "");
  const [hostCode, setHostCode] = useState(value.hostCode ?? "");
  const [path, setPath] = useState(value.path ?? "");

  const handleApply = () => {
    onChange({
      ...value,
      ruleName: ruleName || undefined,
      clientIp: clientIp || undefined,
      hostCode: hostCode || undefined,
      path: path || undefined,
    });
    onApply();
  };

  return (
    <Card size="small" title={<Typography.Text strong>Filters</Typography.Text>}>
      <Space direction="vertical" size="middle" style={{ width: "100%" }}>
        <Select
          allowClear
          placeholder="Action"
          value={value.eventType}
          onChange={(v) => onChange({ ...value, eventType: v })}
          options={[
            { value: "block", label: "Block" },
            { value: "allow", label: "Allow" },
            { value: "challenge", label: "Challenge" },
            { value: "rate_limit", label: "Rate Limit" },
            { value: "log_only", label: "Log Only" },
            { value: "redirect", label: "Redirect" },
          ]}
          style={{ width: "100%" }}
        />

        <Input
          placeholder="Rule Name"
          value={ruleName}
          onChange={(e) => setRuleName(e.target.value)}
          onPressEnter={handleApply}
          allowClear
        />

        <Tooltip title="Exact match — supports both IPv4 and IPv6">
          <Input
            placeholder="Client IP"
            value={clientIp}
            onChange={(e) => setClientIp(e.target.value)}
            onPressEnter={handleApply}
            allowClear
          />
        </Tooltip>

        <Input
          placeholder="Host Code"
          value={hostCode}
          onChange={(e) => setHostCode(e.target.value)}
          onPressEnter={handleApply}
          allowClear
        />

        <Input
          placeholder="Path (contains)"
          value={path}
          onChange={(e) => setPath(e.target.value)}
          onPressEnter={handleApply}
          allowClear
        />

        <Button
          type="primary"
          onClick={handleApply}
          icon={<ReloadOutlined spin={loading} />}
          loading={loading}
          block
        >
          Apply Filters
        </Button>
      </Space>
    </Card>
  );
};

// ─── Filter → Refine CRUD mapping ────────────────────────────────────────────

/** Translate the structured filter state into a Refine-compatible filter array.
 * Field names match `SecurityEventQuery`; the data provider flattens these to
 * `?action=…&rule_name=…` query params. */
export const filtersToCrud = (state: LogsFilterState): import("@refinedev/core").CrudFilter[] => {
  const out: import("@refinedev/core").CrudFilter[] = [];
  if (state.eventType) {
    out.push({ field: "action", operator: "eq", value: state.eventType });
  }
  if (state.ruleName) {
    out.push({ field: "rule_name", operator: "eq", value: state.ruleName });
  }
  if (state.clientIp) {
    out.push({ field: "client_ip", operator: "eq", value: state.clientIp });
  }
  if (state.hostCode) {
    out.push({ field: "host_code", operator: "eq", value: state.hostCode });
  }
  if (state.path) {
    out.push({ field: "path", operator: "contains", value: state.path });
  }
  return out;
};
