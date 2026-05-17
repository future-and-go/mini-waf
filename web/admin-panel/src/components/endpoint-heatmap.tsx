import { Empty, Skeleton, Space, Typography } from "antd";
import { Heatmap } from "@ant-design/plots";
import { useTranslation } from "react-i18next";
import type { EndpointHeatmap as EndpointHeatmapData } from "../types/api";
import { fmtNum } from "../utils/format";

interface EndpointHeatmapProps {
  data: EndpointHeatmapData | undefined;
  loading: boolean;
}

export const EndpointHeatmap: React.FC<EndpointHeatmapProps> = ({ data, loading }) => {
  const { t } = useTranslation();

  if (loading) {
    return <Skeleton active paragraph={{ rows: 6 }} />;
  }

  const cells = data?.cells ?? [];

  if (cells.length === 0) {
    return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t("common.noData")} />;
  }

  return (
    <div>
      <Heatmap
        data={cells}
        xField="category"
        yField="path"
        colorField="count"
        height={320}
        animate={false}
        scale={{
          color: {
            range: ["#fff7e6", "#d4380d"],
          },
        }}
        style={{ inset: 1 }}
        axis={{
          x: { labelAutoRotate: true, labelFontSize: 11 },
          y: { labelFontSize: 11 },
        }}
        legend={false}
        tooltip={{
          items: [
            { field: "path", name: "Path" },
            { field: "category", name: "Category" },
            { field: "count", name: "Count" },
          ],
        }}
      />
      {data?.metadata && (
        <Space
          size="large"
          style={{ marginTop: 8, flexWrap: "wrap" }}
          split={<Typography.Text type="secondary">·</Typography.Text>}
        >
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {t("dashboard.heatmapTotalEvents")}: <strong>{fmtNum(data.metadata.total_events)}</strong>
          </Typography.Text>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {t("dashboard.heatmapPathsSampled")}: <strong>{fmtNum(data.metadata.paths_sampled)}</strong>
          </Typography.Text>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {t("dashboard.heatmapCategoriesTotal")}: <strong>{fmtNum(data.metadata.categories_total)}</strong>
          </Typography.Text>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {t("dashboard.heatmapWindow")}: <strong>{data.metadata.window_hours}h</strong>
          </Typography.Text>
        </Space>
      )}
    </div>
  );
};
