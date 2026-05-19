import { Card, Empty } from "antd";
import { Pie } from "@ant-design/plots";
import { fmtNum } from "../../utils/format";
import type { TopEntry } from "../../types/api";

interface DonutCardProps {
  title: string;
  data: TopEntry[] | undefined;
  colors: Record<string, string>;
  onSliceClick?: (key: string) => void;
  activeKey?: string;
  loading?: boolean;
}

export const DonutCard: React.FC<DonutCardProps> = ({
  title,
  data,
  colors,
  onSliceClick,
  loading,
}) => {
  const rows = Array.isArray(data) ? data : [];
  const total = rows.reduce((s, r) => s + (Number(r.count) || 0), 0);

  return (
    <Card size="small" title={title} loading={loading}>
      {rows.length === 0 ? (
        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />
      ) : (
        <Pie
          data={rows.map((r) => ({ type: r.key, value: Number(r.count) || 0 }))}
          angleField="value"
          colorField="type"
          innerRadius={0.7}
          height={220}
          animate={false}
          legend={{
            position: "right",
            itemName: { style: { fontSize: 11 } },
          }}
          color={({ type }: { type: string }) => colors[type] ?? "#8c8c8c"}
          statistic={{
            title: false,
            content: {
              style: { fontSize: "18px", fontWeight: 600, color: "inherit" },
              content: fmtNum(total),
            },
          }}
          tooltip={{
            formatter: (datum: { type: string; value: number }) => ({
              name: datum.type,
              value: fmtNum(datum.value),
            }),
          }}
          onReady={(plot) => {
            plot.on("element:click", (e: { data?: { data?: { type: string } } }) => {
              const key = e?.data?.data?.type;
              if (key && onSliceClick) onSliceClick(key);
            });
          }}
        />
      )}
    </Card>
  );
};
