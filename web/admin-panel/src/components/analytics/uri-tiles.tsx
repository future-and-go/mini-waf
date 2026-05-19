import { Tooltip } from "antd";
import { fmtNum } from "../../utils/format";

interface UriTile {
  path: string;
  count: number;
}

interface UriTilesProps {
  items: UriTile[];
  onSelect: (path: string) => void;
  activePath?: string;
}

const rankColor = (rank: number, total: number): string => {
  const pct = total > 1 ? rank / (total - 1) : 0;
  // Blue → purple gradient based on rank percentile
  const r = Math.round(22 + pct * (130 - 22));
  const g = Math.round(119 + pct * (0 - 119));
  const b = Math.round(255 + pct * (180 - 255));
  return `rgb(${r},${g},${b})`;
};

export const UriTiles: React.FC<UriTilesProps> = ({ items, onSelect, activePath }) => {
  if (items.length === 0) return null;

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(6, minmax(0, 1fr))",
        gap: 8,
      }}
    >
      {items.map(({ path, count }, idx) => {
        const bg = rankColor(idx, items.length);
        const isActive = activePath === path;

        return (
          <Tooltip key={path} title={path} placement="top">
            <button
              type="button"
              onClick={() => onSelect(path)}
              style={{
                background: bg,
                border: isActive ? "2px solid #fff" : "2px solid transparent",
                borderRadius: 6,
                padding: "8px 6px",
                cursor: "pointer",
                color: "#fff",
                textAlign: "left",
                overflow: "hidden",
                outline: isActive ? "2px solid #1677ff" : "none",
                opacity: activePath && !isActive ? 0.7 : 1,
              }}
            >
              <div
                style={{
                  fontSize: 11,
                  whiteSpace: "nowrap",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  marginBottom: 4,
                }}
              >
                {path}
              </div>
              <div style={{ fontSize: 16, fontWeight: 700 }}>{fmtNum(count)}</div>
            </button>
          </Tooltip>
        );
      })}
    </div>
  );
};
