import { Typography, Space } from "antd";
import type { CSSProperties } from "react";

// Mirrors the engine's threshold gate (`risk/threshold.rs::decide`):
//   score < allow   → Allow
//   score >= block  → Block
//   otherwise       → Challenge
// Only `allow` and `block` are enforcement boundaries — there is no fourth
// band and the tier's `challenge` value is not consulted by the gate.
interface RiskBandPreviewProps {
  allow: number;
  block: number;
  hideLegend?: boolean;
  style?: CSSProperties;
}

const BAND_COLORS = {
  allow: "#52c41a",
  challenge: "#faad14",
  block: "#f5222d",
} as const;

export const RiskBandPreview: React.FC<RiskBandPreviewProps> = ({
  allow,
  block,
  hideLegend,
  style,
}) => {
  const a = Math.max(0, Math.min(100, allow));
  const b = Math.max(a, Math.min(100, block));

  const greenPct = a;
  const yellowPct = b - a;
  const redPct = 100 - b;

  return (
    <Space direction="vertical" size={6} style={{ width: "100%", ...style }}>
      <div style={{ display: "flex", height: 20, borderRadius: 3, overflow: "hidden" }}>
        {greenPct > 0 && (
          <div
            title={`Allow: score < ${a}`}
            style={{ width: `${greenPct}%`, background: BAND_COLORS.allow }}
          />
        )}
        {yellowPct > 0 && (
          <div
            title={`Challenge: ${a} ≤ score < ${b}`}
            style={{ width: `${yellowPct}%`, background: BAND_COLORS.challenge }}
          />
        )}
        {redPct > 0 && (
          <div
            title={`Block: score ≥ ${b}`}
            style={{ width: `${redPct}%`, background: BAND_COLORS.block }}
          />
        )}
      </div>
      {!hideLegend && (
        <div style={{ display: "flex", flexWrap: "wrap", gap: "2px 14px" }}>
          <Typography.Text type="secondary" style={{ fontSize: 11 }}>
            <span style={{ color: BAND_COLORS.allow }}>■</span> Allow &lt; {a}
          </Typography.Text>
          <Typography.Text type="secondary" style={{ fontSize: 11 }}>
            <span style={{ color: BAND_COLORS.challenge }}>■</span> Challenge {a}–{b - 1}
          </Typography.Text>
          <Typography.Text type="secondary" style={{ fontSize: 11 }}>
            <span style={{ color: BAND_COLORS.block }}>■</span> Block ≥ {b}
          </Typography.Text>
        </div>
      )}
    </Space>
  );
};
