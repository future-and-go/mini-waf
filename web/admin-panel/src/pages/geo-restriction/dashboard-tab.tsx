import { Row, Col, Card, Alert, Empty, Typography } from "antd";
import {
  GlobalOutlined,
  StopOutlined,
  AlertOutlined,
  EnvironmentOutlined,
} from "@ant-design/icons";
import { useCustom } from "@refinedev/core";
import { useTranslation } from "react-i18next";
import { useMemo } from "react";
import { Pie, Bar } from "@ant-design/plots";
import { KpiCard } from "../../components/kpi-card";
import { TopList } from "../../components/top-list";
import { CategoryBars } from "../../components/category-bars";
import { fmtNum } from "../../utils/format";
import type { TopEntry } from "../../types/api";
import {
  countryLabel,
  type GeoStatsResponse,
  type GeoDistEntry,
  type GeoRule,
} from "./geo-shared";

const PALETTE = [
  "#1677ff", "#f5222d", "#fa8c16", "#722ed1", "#13c2c2",
  "#52c41a", "#eb2f96", "#2f54eb", "#faad14", "#08979c",
];

export const DashboardTab: React.FC = () => {
  const { t } = useTranslation();

  const geo = useCustom<GeoStatsResponse>({
    url: "/api/stats/geo",
    method: "get",
    queryOptions: { staleTime: 60_000 },
    errorNotification: false,
  });

  const rulesQuery = useCustom<GeoRule[]>({
    url: "/api/geoip/rules",
    method: "get",
    queryOptions: { staleTime: 30_000 },
    errorNotification: false,
  });

  // The data provider already unwraps one envelope level, so the geo payload
  // sits directly at `result.data` (mirrors the Rule Analytics overview binding).
  const statsData = geo.result?.data as GeoStatsResponse | undefined;
  const topCountries: TopEntry[] = Array.isArray(statsData?.top_countries) ? statsData!.top_countries : [];
  const topCities: TopEntry[] = Array.isArray(statsData?.top_cities) ? statsData!.top_cities : [];
  const topIsps: TopEntry[] = Array.isArray(statsData?.top_isps) ? statsData!.top_isps : [];
  const countryDist: GeoDistEntry[] = Array.isArray(statsData?.country_distribution)
    ? statsData!.country_distribution
    : [];

  const rules: GeoRule[] = (() => {
    const raw = rulesQuery.result?.data;
    if (!raw) return [];
    if (Array.isArray(raw)) return raw;
    if (Array.isArray((raw as { data: GeoRule[] }).data)) return (raw as { data: GeoRule[] }).data;
    return [];
  })();

  const activeRules = rules.filter((r) => r.enabled).length;
  const blockedCountries = rules.filter((r) => r.action === "block" && r.enabled).length;
  const geoEvents = topCountries.reduce((s, c) => s + (Number(c.count) || 0), 0);
  const topSource = countryDist[0]
    ? countryLabel(countryDist[0].iso_code, countryDist[0].country)
    : "—";

  // Donut: top 6 countries by iso_code distribution + rolled-up "Others".
  const donutData = useMemo(() => {
    const sorted = [...countryDist].sort((a, b) => (Number(b.count) || 0) - (Number(a.count) || 0));
    const top = sorted.slice(0, 6);
    const restTotal = sorted.slice(6).reduce((s, c) => s + (Number(c.count) || 0), 0);
    const rows = top.map((c) => ({
      type: countryLabel(c.iso_code, c.country),
      value: Number(c.count) || 0,
    }));
    if (restTotal > 0) {
      rows.push({ type: t("geo.dashboard.others", { defaultValue: "Others" }), value: restTotal });
    }
    return rows;
  }, [countryDist, t]);

  const donutColors = useMemo(() => {
    const map: Record<string, string> = {};
    donutData.forEach((d, i) => {
      map[d.type] = PALETTE[i % PALETTE.length];
    });
    return map;
  }, [donutData]);

  const donutTotal = donutData.reduce((s, d) => s + d.value, 0);

  // Source map (Option A): ranked country bars with flags. A true choropleth
  // needs a GeoIP DB + map layer (Option C) — see plan.
  const sourceMapItems = useMemo(
    () =>
      countryDist.slice(0, 20).map((c) => ({
        key: countryLabel(c.iso_code, c.country),
        count: Number(c.count) || 0,
      })),
    [countryDist],
  );
  const sourceMapColors = useMemo(() => {
    const map: Record<string, string> = {};
    sourceMapItems.forEach((it, i) => {
      map[it.key] = PALETTE[i % PALETTE.length];
    });
    return map;
  }, [sourceMapItems]);

  const geoError = geo.query.isError;
  const geoLoading = geo.query.isLoading;

  return (
    <Row gutter={[12, 12]}>
      {/* ── KPI strip ───────────────────────────────────────────────────── */}
      <Col xs={24} sm={12} xl={6}>
        <KpiCard
          label={t("geo.dashboard.activeRules", { defaultValue: "Active geo rules" })}
          value={activeRules}
          icon={GlobalOutlined}
          color="blue"
          loading={rulesQuery.query.isLoading}
        />
      </Col>
      <Col xs={24} sm={12} xl={6}>
        <KpiCard
          label={t("geo.dashboard.blockedCountries", { defaultValue: "Blocked countries" })}
          value={blockedCountries}
          icon={StopOutlined}
          color="red"
          loading={rulesQuery.query.isLoading}
        />
      </Col>
      <Col xs={24} sm={12} xl={6}>
        <KpiCard
          label={t("geo.dashboard.geoEvents", { defaultValue: "Geo-attributed events" })}
          value={fmtNum(geoEvents)}
          icon={AlertOutlined}
          color="orange"
          loading={geoLoading}
        />
      </Col>
      <Col xs={24} sm={12} xl={6}>
        <KpiCard
          label={t("geo.dashboard.topSource", { defaultValue: "Top source country" })}
          value={topSource}
          icon={EnvironmentOutlined}
          color="purple"
          loading={geoLoading}
        />
      </Col>

      {/* ── Distribution donut + top sources bar ────────────────────────── */}
      <Col xs={24} lg={10}>
        <Card
          size="small"
          title={t("geo.dashboard.distribution", { defaultValue: "Country Attack Distribution" })}
          loading={geoLoading}
        >
          {geoError ? (
            <Alert
              type="warning"
              showIcon
              message={t("geo.statsUnavailable", { defaultValue: "Geo stats unavailable" })}
            />
          ) : donutData.length === 0 ? (
            <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />
          ) : (
            <Pie
              data={donutData}
              angleField="value"
              colorField="type"
              innerRadius={0.6}
              height={260}
              animate={false}
              legend={{ position: "right", itemName: { style: { fontSize: 11 } } }}
              color={({ type }: { type: string }) => donutColors[type] ?? "#8c8c8c"}
              statistic={{
                title: false,
                content: {
                  style: { fontSize: "18px", fontWeight: 600, color: "inherit" },
                  content: fmtNum(donutTotal),
                },
              }}
              tooltip={{
                formatter: (datum: { type: string; value: number }) => ({
                  name: datum.type,
                  value: fmtNum(datum.value),
                }),
              }}
            />
          )}
        </Card>
      </Col>
      <Col xs={24} lg={14}>
        <Card
          size="small"
          title={t("geo.dashboard.topSources", { defaultValue: "Top Attack Source Countries" })}
          loading={geoLoading}
        >
          {geoError ? (
            <Alert
              type="warning"
              showIcon
              message={t("geo.statsUnavailable", { defaultValue: "Geo stats unavailable" })}
            />
          ) : topCountries.length === 0 ? (
            <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />
          ) : (
            <Bar
              data={topCountries.slice(0, 10).map((c) => ({ key: c.key, count: Number(c.count) || 0 }))}
              xField="key"
              yField="count"
              height={300}
              animate={false}
              legend={false}
              color="#1677ff"
              label={{ text: "count", position: "right", style: { fontSize: 11 } }}
              tooltip={{
                formatter: (datum: { key: string; count: number }) => ({
                  name: datum.key,
                  value: fmtNum(datum.count),
                }),
              }}
            />
          )}
        </Card>
      </Col>

      {/* ── Source map (ranked, with flags) ─────────────────────────────── */}
      <Col xs={24}>
        <Card
          size="small"
          title={t("geo.dashboard.sourceMap", {
            defaultValue: "Application Security Events Source Map",
          })}
          loading={geoLoading}
          extra={
            <Typography.Text type="secondary" style={{ fontSize: 11 }}>
              {t("geo.dashboard.mapHint", {
                defaultValue: "Choropleth requires GeoIP DB + map layer (optional)",
              })}
            </Typography.Text>
          }
        >
          {geoError ? (
            <Alert
              type="warning"
              showIcon
              message={t("geo.statsUnavailable", { defaultValue: "Geo stats unavailable" })}
            />
          ) : sourceMapItems.length === 0 ? (
            <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />
          ) : (
            <CategoryBars items={sourceMapItems} colors={sourceMapColors} />
          )}
        </Card>
      </Col>

      {/* ── Top cities + ISPs ───────────────────────────────────────────── */}
      <Col xs={24} lg={12}>
        <TopList
          title={t("geo.dashboard.topCities", { defaultValue: "Top Source Cities" })}
          items={topCities}
          icon={EnvironmentOutlined}
          badgeColor="#13c2c2"
        />
      </Col>
      <Col xs={24} lg={12}>
        <TopList
          title={t("geo.dashboard.topIsps", { defaultValue: "Top Source Networks (ISP)" })}
          items={topIsps}
          icon={GlobalOutlined}
          badgeColor="#722ed1"
        />
      </Col>
    </Row>
  );
};
