import { Typography, Space, Card, Skeleton, Result, Button, Alert } from "antd";
import { ReloadOutlined } from "@ant-design/icons";
import { useTranslation } from "react-i18next";

import { useEnforcementCapabilities } from "../../hooks/use-enforcement-capabilities";
import { DefaultModeControl } from "./default-mode-control";
import { CapabilityCatalog } from "./capability-catalog";
import { RuntimeOperations } from "./runtime-operations";
import { PlaneMap } from "./plane-map";

const { Title, Paragraph } = Typography;

// Control-plane console (E10). Owns the shared capabilities query; the header
// dial, catalog, runtime ops, and plane map all read from this one snapshot.
export const EnforcementConsolePage: React.FC = () => {
  const { t } = useTranslation();
  const { result, query } = useEnforcementCapabilities();
  const caps = result?.data;

  const disabled = (query.error as { statusCode?: number } | null)?.statusCode === 404;

  return (
    <div style={{ maxWidth: 1200, margin: "0 auto" }}>
      <Space direction="vertical" size={16} style={{ width: "100%" }}>
        <div>
          <Title level={3} style={{ marginBottom: 4 }}>{t("enforcement.title")}</Title>
          <Paragraph type="secondary" style={{ marginBottom: 0 }}>{t("enforcement.subtitle")}</Paragraph>
        </div>

        {disabled ? (
          <Result status="info" title={t("enforcement.disabledTitle")} subTitle={t("enforcement.disabledMessage")} />
        ) : query.isLoading ? (
          <Card><Skeleton active paragraph={{ rows: 8 }} /></Card>
        ) : query.isError ? (
          <Alert
            type="error"
            showIcon
            message={t("enforcement.loadError")}
            action={
              <Button size="small" icon={<ReloadOutlined />} onClick={() => query.refetch()}>
                {t("enforcement.retry")}
              </Button>
            }
          />
        ) : caps ? (
          <>
            <Card>
              <DefaultModeControl
                defaultMode={caps.active.default_mode}
                dataUpdatedAt={query.dataUpdatedAt}
                isFetching={query.isFetching}
                onRefetch={() => query.refetch()}
              />
            </Card>
            <CapabilityCatalog
              features={caps.features}
              active={caps.active}
              onRefetch={() => query.refetch()}
            />
            <RuntimeOperations onRefetch={() => query.refetch()} />
            <PlaneMap />
          </>
        ) : null}
      </Space>
    </div>
  );
};
