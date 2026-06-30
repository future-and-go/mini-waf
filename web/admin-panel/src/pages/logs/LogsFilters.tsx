import { useState } from "react";
import { Alert, Card, Space, Select, Input, Button, DatePicker, Tooltip, Typography } from "antd";
import { ReloadOutlined } from "@ant-design/icons";
import dayjs from "dayjs";

// ─── Public types ─────────────────────────────────────────────────────────────

/** Absolute time window as `[from, to]` RFC3339 (Z-suffixed) strings. */
export type LogsRange = [string, string];

export interface LogsFilterState {
  /** Enforcement action — maps to the `action` query param. */
  eventType?: string;
  ruleName?: string;
  clientIp?: string;
  hostCode?: string;
  path?: string;
  /** Selected protection tiers — maps to the comma-joined `tier` param. */
  tiers: string[];
  /** Absolute time window — maps to `created_at_from` / `created_at_to`. */
  range?: LogsRange;
}

/** Exact tier strings — must match the Debug-formatted enum the backend stores
 *  (see decision record: do not switch to serde snake_case). */
const TIER_OPTIONS = [
  { value: "Critical", label: "Critical" },
  { value: "High", label: "High" },
  { value: "Medium", label: "Medium" },
  { value: "CatchAll", label: "Catch-All" },
];

// Default: last 1 hour, no tier filter. Matches the original pre-rewire UX and
// bounds the common-case COUNT cost. Computed at mount so "now" is current.
export const defaultLogsFilters = (): LogsFilterState => {
  const end = dayjs();
  return { tiers: [], range: [end.subtract(1, "hour").toISOString(), end.toISOString()] };
};

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
 * Apply. Tier and time-range changes apply immediately (no text debounce).
 *
 * Filters map 1:1 onto `SecurityEventQuery` fields served by
 * `/api/security-events`.
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

  // Presets compute [now - delta, now] and apply immediately.
  const applyPreset = (delta: { hours?: number; days?: number }) => {
    const end = dayjs();
    const start = delta.hours ? end.subtract(delta.hours, "hour") : end.subtract(delta.days ?? 1, "day");
    onChange({ ...value, range: [start.toISOString(), end.toISOString()] });
    onApply();
  };

  return (
    <Card size="small" title={<Typography.Text strong>Filters</Typography.Text>}>
      <Space direction="vertical" size="middle" style={{ width: "100%" }}>
        <Space size={4} wrap>
          <Button size="small" onClick={() => applyPreset({ hours: 1 })}>
            1h
          </Button>
          <Button size="small" onClick={() => applyPreset({ hours: 6 })}>
            6h
          </Button>
          <Button size="small" onClick={() => applyPreset({ hours: 24 })}>
            24h
          </Button>
          <Button size="small" onClick={() => applyPreset({ days: 7 })}>
            7d
          </Button>
        </Space>

        <DatePicker.RangePicker
          showTime
          allowClear
          style={{ width: "100%" }}
          value={value.range ? [dayjs(value.range[0]), dayjs(value.range[1])] : null}
          onChange={(vals) => {
            if (vals && vals[0] && vals[1]) {
              // toISOString() yields Z-suffixed RFC3339 — never a +00:00 offset,
              // whose `+` would URL-decode to a space and 400 the request.
              onChange({ ...value, range: [vals[0].toISOString(), vals[1].toISOString()] });
            } else {
              onChange({ ...value, range: undefined });
            }
          }}
        />

        <Select
          mode="multiple"
          allowClear
          placeholder="Tier"
          value={value.tiers}
          onChange={(v) => onChange({ ...value, tiers: v })}
          options={TIER_OPTIONS}
          style={{ width: "100%" }}
        />

        {value.tiers.length > 0 && (
          <Alert
            type="info"
            showIcon
            style={{ fontSize: 12 }}
            message="Events recorded before the tier rollout have no tier and are excluded while a tier filter is active."
          />
        )}

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
  // Omit tier entirely when nothing is selected — emitting tier="" would zero
  // out results (the backend's `tier = ANY(string_to_array('', ','))`).
  if (state.tiers.length > 0) {
    out.push({ field: "tier", operator: "eq", value: state.tiers.join(",") });
  }
  if (state.range) {
    out.push({ field: "created_at_from", operator: "gte", value: state.range[0] });
    out.push({ field: "created_at_to", operator: "lte", value: state.range[1] });
  }
  return out;
};
