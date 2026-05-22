import { Typography, Space } from "antd";
import type { CSSProperties } from "react";

interface RiskBandPreviewProps {
  riskAllow: number;
  riskChallenge: number;
  riskBlock: number;
  style?: CSSProperties;
}

const BAND_COLORS = {
  allow: "#52c41a",
  challenge: "#faad14",
  nearBlock: "#fa8c16",
  block: "#f5222d",
} as const;

export const RiskBandPreview: React.FC<RiskBandPreviewProps> = ({
  riskAllow,
  riskChallenge,
  riskBlock,
  style,
}) => {
  const a = Math.max(0, Math.min(100, riskAllow));
  const c = Math.max(0, Math.min(100, riskChallenge));
  const b = Math.max(0, Math.min(100, riskBlock));

  const greenPct = a;
  const yellowPct = Math.max(0, c - a);
  const orangePct = Math.max(0, b - c);
  const redPct = Math.max(0, 100 - b);

  return (
    <Space direction="vertical" size={6} style={{ width: "100%", ...style }}>
      <div style={{ display: "flex", height: 20, borderRadius: 3, overflow: "hidden" }}>
        {greenPct > 0 && (
          <div
            title={`Allow: 0–${a}`}
            style={{ width: `${greenPct}%`, background: BAND_COLORS.allow }}
          />
        )}
        {yellowPct > 0 && (
          <div
            title={`Challenge: ${a}–${c}`}
            style={{ width: `${yellowPct}%`, background: BAND_COLORS.challenge }}
          />
        )}
        {orangePct > 0 && (
          <div
            title={`Block threshold: ${c}–${b}`}
            style={{ width: `${orangePct}%`, background: BAND_COLORS.nearBlock }}
          />
        )}
        {redPct > 0 && (
          <div
            title={`Block: ${b}–100`}
            style={{ width: `${redPct}%`, background: BAND_COLORS.block }}
          />
        )}
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: "2px 14px" }}>
        <Typography.Text type="secondary" style={{ fontSize: 11 }}>
          <span style={{ color: BAND_COLORS.allow }}>■</span> Allow 0–{a}
        </Typography.Text>
        <Typography.Text type="secondary" style={{ fontSize: 11 }}>
          <span style={{ color: BAND_COLORS.challenge }}>■</span> Challenge {a}–{c}
        </Typography.Text>
        <Typography.Text type="secondary" style={{ fontSize: 11 }}>
          <span style={{ color: BAND_COLORS.nearBlock }}>■</span> Block {c}–{b}
        </Typography.Text>
        <Typography.Text type="secondary" style={{ fontSize: 11 }}>
          <span style={{ color: BAND_COLORS.block }}>■</span> Hard block {b}–100
        </Typography.Text>
      </div>
    </Space>
  );
};
