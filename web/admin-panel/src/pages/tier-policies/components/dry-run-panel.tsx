import { Space, Select, Input, Button, Alert, Tag } from "antd";
import { PlayCircleOutlined } from "@ant-design/icons";
import type { TFunction } from "i18next";
import { HTTP_METHODS, TIER_COLOR, type DryRunResponse, type TierKey } from "../types";

interface DryRunPanelProps {
  method: string;
  host: string;
  path: string;
  result: DryRunResponse | null;
  running: boolean;
  disabled: boolean;
  onMethodChange: (m: string) => void;
  onHostChange: (h: string) => void;
  onPathChange: (p: string) => void;
  onRun: () => void;
  t: TFunction;
}

export const DryRunPanel: React.FC<DryRunPanelProps> = ({
  method,
  host,
  path,
  result,
  running,
  disabled,
  onMethodChange,
  onHostChange,
  onPathChange,
  onRun,
  t,
}) => (
  <>
    <Space wrap>
      <Select
        value={method}
        onChange={onMethodChange}
        style={{ width: 100 }}
        options={HTTP_METHODS.map((m) => ({ value: m, label: m }))}
      />
      <Input
        placeholder={t("tierPolicies.testHost")}
        value={host}
        onChange={(e) => onHostChange(e.target.value)}
        style={{ width: 220 }}
      />
      <Input
        placeholder={t("tierPolicies.testPath")}
        value={path}
        onChange={(e) => onPathChange(e.target.value)}
        style={{ width: 220 }}
      />
      <Button
        type="primary"
        icon={<PlayCircleOutlined />}
        loading={running}
        onClick={onRun}
        disabled={disabled}
      >
        {t("tierPolicies.run")}
      </Button>
    </Space>
    {result && (
      <div style={{ marginTop: 12 }}>
        <Alert
          type="info"
          showIcon
          message={
            <Space>
              <span>{t("tierPolicies.matchedTier")}:</span>
              <Tag color={TIER_COLOR[result.matched_tier as TierKey] ?? "default"}>
                {result.matched_tier}
              </Tag>
              {result.matched_rule_id !== undefined && (
                <span style={{ color: "#8c8c8c", fontSize: 12 }}>
                  {t("tierPolicies.ruleId")}: #{result.matched_rule_id}
                </span>
              )}
            </Space>
          }
        />
      </div>
    )}
  </>
);
