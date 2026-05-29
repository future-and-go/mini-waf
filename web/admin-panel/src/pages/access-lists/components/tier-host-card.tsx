import { Space, Typography, Segmented, Popconfirm, Input, Button, Tag } from "antd";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { WHITELIST_MODES, type Tier } from "../types";

interface TierHostCardProps {
  tier: Tier;
  hosts: string[];
  mode: string;
  disabled?: boolean;
  onHostsChange: (tier: Tier, hosts: string[]) => void;
  onModeChange: (tier: Tier, mode: string) => void;
}

export const TierHostCard: React.FC<TierHostCardProps> = ({
  tier,
  hosts,
  mode,
  disabled,
  onHostsChange,
  onModeChange,
}) => {
  const [input, setInput] = useState("");
  const [localHosts, setLocalHosts] = useState<string[]>(hosts);
  const { t } = useTranslation();

  useEffect(() => {
    setLocalHosts(hosts);
  }, [hosts]);

  const addHost = () => {
    const v = input.trim();
    if (v && !localHosts.includes(v)) {
      const next = [...localHosts, v];
      setLocalHosts(next);
      onHostsChange(tier, next);
    }
    setInput("");
  };

  const removeHost = (h: string) => {
    const next = localHosts.filter((x) => x !== h);
    setLocalHosts(next);
    onHostsChange(tier, next);
  };

  const isCriticalFullBypass = tier === "critical" && mode === "full_bypass";

  return (
    <Space direction="vertical" style={{ width: "100%" }} size="small">
      <Space align="center">
        <Typography.Text strong>{t("accessLists.tierMode")}</Typography.Text>
        {isCriticalFullBypass ? (
          <Popconfirm
            title={t("accessLists.criticalBypassWarning")}
            description={t("accessLists.criticalBypassDesc")}
            onConfirm={() => onModeChange(tier, "full_bypass")}
            okType="danger"
            disabled={disabled}
          >
            <Segmented value={mode} options={WHITELIST_MODES} disabled={disabled} />
          </Popconfirm>
        ) : (
          <Segmented
            value={mode}
            options={WHITELIST_MODES}
            onChange={(v) => onModeChange(tier, String(v))}
            disabled={disabled}
          />
        )}
      </Space>
      <Space.Compact style={{ width: "100%" }}>
        <Input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="example.com"
          onPressEnter={addHost}
          disabled={disabled}
        />
        <Button onClick={addHost} disabled={disabled}>
          {t("common.add")}
        </Button>
      </Space.Compact>
      <Space wrap size={[4, 4]}>
        {localHosts.length === 0 ? (
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {t("accessLists.noHosts")}
          </Typography.Text>
        ) : (
          localHosts.map((h) => (
            <Tag
              key={h}
              closable={!disabled}
              onClose={() => removeHost(h)}
              style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}
            >
              {h}
            </Tag>
          ))
        )}
      </Space>
    </Space>
  );
};
