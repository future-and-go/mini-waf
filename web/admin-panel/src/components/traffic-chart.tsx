import { Line } from "@ant-design/plots";
import dayjs from "dayjs";
import { Empty } from "antd";
import { useMemo } from "react";
import type { TrafficPoint } from "../types/api";

interface TrafficChartProps {
  series: TrafficPoint[];
}

// Two overlaid lines: total + blocked. The waf-api timeseries endpoint
// returns one TrafficPoint[] with both fields, so we flatten into a long
// shape that AntD Plots' Line consumes directly.
export const TrafficChart: React.FC<TrafficChartProps> = ({ series }) => {
  const data = useMemo(() => {
    const out: { ts: string; value: number; series: string }[] = [];
    // Defensive: `series` may arrive as a non-array (e.g. an envelope object)
    // if the upstream useCustom wrapping shape changes. Iterating with for-of
    // on a non-iterable throws `(e ?? []) is not iterable`.
    const points = Array.isArray(series) ? series : [];
    for (const p of points) {
      const ts = dayjs(p.ts).format("HH:mm");
      out.push({ ts, value: Number(p.total) || 0, series: "total" });
      out.push({ ts, value: Number(p.blocked) || 0, series: "blocked" });
    }
    return out;
  }, [series]);

  if (!data.length) {
    return <Empty description="No traffic data yet" style={{ padding: 32 }} />;
  }

  return (
    <Line
      data={data}
      xField="ts"
      yField="value"
      seriesField="series"
      height={220}
      smooth
      animate={false}
      legend={false}
      color={["#1677ff", "#f5222d"]}
      point={{ size: 2 }}
      xAxis={{ tickCount: 6 }}
    />
  );
};
