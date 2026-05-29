import { Card, Form, Radio, InputNumber, Select, Space, Slider, Tag } from "antd";
import React, { useCallback, useEffect, useRef, useState } from "react";
import { DEFAULT_POLICY, TIER_COLOR, type TierKey, type TierPolicy } from "../types";

interface PolicyCardProps {
  tierKey: TierKey;
  label: string;
  policy: TierPolicy;
  onChange: (p: TierPolicy) => void;
  disabled?: boolean;
  t: (key: string) => string;
}

// Stable tooltip config — defined outside component to avoid new object on every render.
const SLIDER_TOOLTIP = { formatter: (v?: number) => `${v ?? 0}` };

export const PolicyCard: React.FC<PolicyCardProps> = React.memo(
  ({ tierKey, label, policy: policyProp, onChange, disabled, t }) => {
    const policy = policyProp ?? DEFAULT_POLICY;
    const color = TIER_COLOR[tierKey];

    // Local threshold state so slider drags don't re-render parent on every pixel;
    // parent is notified via onAfterChange (mouse-up / keyboard-end).
    const [localThresh, setLocalThresh] = useState(
      () => policy.risk_thresholds ?? { allow: 20, challenge: 60, block: 85 },
    );

    const onChangeRef = useRef(onChange);
    const policyRef = useRef(policy);
    const localThreshRef = useRef(localThresh);
    onChangeRef.current = onChange;
    policyRef.current = policy;
    localThreshRef.current = localThresh;

    useEffect(() => {
      const incoming = policy.risk_thresholds ?? { allow: 20, challenge: 60, block: 85 };
      const cur = localThreshRef.current;
      if (
        incoming.allow !== cur.allow ||
        incoming.challenge !== cur.challenge ||
        incoming.block !== cur.block
      ) {
        setLocalThresh(incoming);
      }
      // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [policy.risk_thresholds]);

    const setField = useCallback(
      <K extends keyof TierPolicy>(key: K, val: TierPolicy[K]) =>
        onChangeRef.current({ ...policyRef.current, [key]: val }),
      [],
    );

    const onSliderChange = useCallback((field: "allow" | "challenge" | "block", val: number) => {
      setLocalThresh((prev) => ({ ...prev, [field]: val }));
    }, []);

    const onSliderCommit = useCallback((field: "allow" | "challenge" | "block", val: number) => {
      setLocalThresh((prev) => {
        const next = { ...prev, [field]: val };
        onChangeRef.current({ ...policyRef.current, risk_thresholds: next });
        return next;
      });
    }, []);

    const { allow, challenge, block } = localThresh;
    const thresholdsValid = allow < challenge && challenge < block;

    return (
      <Card
        size="small"
        title={
          <Tag color={color} style={{ fontWeight: 600 }}>
            {label.toUpperCase()}
          </Tag>
        }
        style={{ height: "100%" }}
      >
        <Form layout="vertical" size="small" disabled={disabled}>
          <Form.Item label={t("tierPolicies.failMode")}>
            <Radio.Group
              value={policy.fail_mode}
              onChange={(e) => setField("fail_mode", e.target.value)}
            >
              <Radio value="close">{t("tierPolicies.failClose")}</Radio>
              <Radio value="open">{t("tierPolicies.failOpen")}</Radio>
            </Radio.Group>
          </Form.Item>

          <Form.Item label={t("tierPolicies.ddosThreshold")}>
            <InputNumber
              min={1}
              max={100000}
              value={policy.ddos_threshold_rps}
              onChange={(v) => v !== null && setField("ddos_threshold_rps", v)}
              addonAfter="rps"
              style={{ width: "100%" }}
            />
          </Form.Item>

          <Form.Item label={t("tierPolicies.cachePolicy")}>
            <Select
              value={policy.cache_policy}
              onChange={(v) => setField("cache_policy", v)}
              style={{ width: "100%" }}
              options={[
                { value: "no_cache", label: t("tierPolicies.cacheNoCache") },
                { value: "short_ttl", label: t("tierPolicies.cacheShortTtl") },
                { value: "aggressive", label: t("tierPolicies.cacheAggressive") },
                { value: "default", label: t("tierPolicies.cacheDefault") },
              ]}
            />
          </Form.Item>

          <Form.Item
            label={t("tierPolicies.riskThresholds")}
            validateStatus={thresholdsValid ? "" : "error"}
            help={thresholdsValid ? undefined : t("tierPolicies.thresholdError")}
          >
            <Space direction="vertical" style={{ width: "100%" }} size={2}>
              <ThresholdRow
                label={t("tierPolicies.allow")}
                color="green"
                value={allow}
                onChange={(v) => onSliderChange("allow", v)}
                onCommit={(v) => onSliderCommit("allow", v)}
                tooltip={SLIDER_TOOLTIP}
              />
              <ThresholdRow
                label={t("tierPolicies.challenge")}
                color="orange"
                value={challenge}
                onChange={(v) => onSliderChange("challenge", v)}
                onCommit={(v) => onSliderCommit("challenge", v)}
                tooltip={SLIDER_TOOLTIP}
              />
              <ThresholdRow
                label={t("tierPolicies.block")}
                color="red"
                value={block}
                onChange={(v) => onSliderChange("block", v)}
                onCommit={(v) => onSliderCommit("block", v)}
                tooltip={SLIDER_TOOLTIP}
              />
            </Space>
          </Form.Item>
        </Form>
      </Card>
    );
  },
);
PolicyCard.displayName = "PolicyCard";

interface ThresholdRowProps {
  label: string;
  color: string;
  value: number;
  onChange: (v: number) => void;
  onCommit: (v: number) => void;
  tooltip: { formatter: (v?: number) => string };
}

const ThresholdRow: React.FC<ThresholdRowProps> = ({ label, color, value, onChange, onCommit, tooltip }) => (
  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
    <Tag color={color} style={{ width: 70, textAlign: "center" }}>
      {label}
    </Tag>
    <Slider
      min={0}
      max={100}
      value={value}
      onChange={onChange}
      onAfterChange={onCommit}
      style={{ flex: 1 }}
      tooltip={tooltip}
    />
    <span style={{ width: 28, textAlign: "right", fontSize: 12 }}>{value}</span>
  </div>
);
