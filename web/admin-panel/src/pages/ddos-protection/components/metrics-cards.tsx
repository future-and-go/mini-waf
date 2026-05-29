import { Row, Col } from "antd";
import {
  StopOutlined,
  FireOutlined,
  WarningOutlined,
  DatabaseOutlined,
  ThunderboltOutlined,
  UserOutlined,
  AimOutlined,
  ApartmentOutlined,
} from "@ant-design/icons";
import type { TFunction } from "i18next";
import { KpiCard } from "../../../components/kpi-card";
import type { DdosMetrics } from "../types";

interface MetricsCardsProps {
  metrics?: DdosMetrics;
  loading: boolean;
  t: TFunction;
}

export const MetricsCards: React.FC<MetricsCardsProps> = ({ metrics, loading, t }) => (
  <Row gutter={[12, 12]}>
    <Col xs={12} sm={6}>
      <KpiCard
        label={t("ddos.activeBans")}
        value={metrics?.active_bans ?? "—"}
        icon={StopOutlined}
        color="red"
        loading={loading}
      />
    </Col>
    <Col xs={12} sm={6}>
      <KpiCard
        label={t("ddos.bansTotal")}
        value={metrics?.bans_total ?? "—"}
        icon={WarningOutlined}
        color="purple"
        loading={loading}
      />
    </Col>
    <Col xs={12} sm={6}>
      <KpiCard
        label={t("ddos.burstsTotal")}
        value={metrics?.bursts_total ?? "—"}
        icon={FireOutlined}
        color="orange"
        loading={loading}
      />
    </Col>
    <Col xs={12} sm={6}>
      <KpiCard
        label={t("ddos.degradeEvents")}
        value={metrics?.degrade_events ?? "—"}
        icon={ThunderboltOutlined}
        color={metrics?.degrade_events ? "orange" : "green"}
        loading={loading}
      />
    </Col>
    <Col xs={12} sm={6}>
      <KpiCard
        label={t("ddos.burstsPerIp")}
        value={metrics?.bursts_per_ip ?? "—"}
        icon={UserOutlined}
        color="blue"
        loading={loading}
      />
    </Col>
    <Col xs={12} sm={6}>
      <KpiCard
        label={t("ddos.burstsPerFp")}
        value={metrics?.bursts_per_fp ?? "—"}
        icon={AimOutlined}
        color="teal"
        loading={loading}
      />
    </Col>
    <Col xs={12} sm={6}>
      <KpiCard
        label={t("ddos.burstsPerTier")}
        value={metrics?.bursts_per_tier ?? "—"}
        icon={ApartmentOutlined}
        color="indigo"
        loading={loading}
      />
    </Col>
    <Col xs={12} sm={6}>
      <KpiCard
        label={t("ddos.storeErrors")}
        value={metrics?.store_errors ?? "—"}
        icon={DatabaseOutlined}
        color={metrics?.store_errors ? "red" : "green"}
        loading={loading}
      />
    </Col>
  </Row>
);
