import { Space, Tabs, Typography } from "antd";
import { useTranslation } from "react-i18next";
import { DashboardTab } from "./dashboard-tab";
import { RulesTab } from "./rules-tab";

export const GeoRestrictionPage: React.FC = () => {
  const { t } = useTranslation();

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <div>
        <Typography.Title level={4} style={{ margin: 0 }}>
          {t("geo.title", { defaultValue: "Geo Restriction (FR-041)" })}
        </Typography.Title>
        <Typography.Text type="secondary">
          {t("geo.subtitle", { defaultValue: "Block or allow requests by country via GeoIP" })}
        </Typography.Text>
      </div>

      <Tabs
        defaultActiveKey="dashboard"
        items={[
          {
            key: "dashboard",
            label: t("geo.tabs.dashboard", { defaultValue: "Dashboard" }),
            children: <DashboardTab />,
          },
          {
            key: "rules",
            label: t("geo.tabs.rules", { defaultValue: "Country Rules" }),
            children: <RulesTab />,
          },
        ]}
      />
    </Space>
  );
};
