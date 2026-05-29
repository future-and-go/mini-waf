import { Alert, App as AntdApp, Badge, Card, Col, Row, Space, Tabs } from "antd";
import { useCustom, useCustomMutation, useGetIdentity } from "@refinedev/core";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { IpListCard } from "./components/ip-list-card";
import { TierHostCard } from "./components/tier-host-card";
import { DecisionTester } from "./components/decision-tester";
import { PageHeader } from "./components/page-header";
import {
  DEFAULT_CONFIG,
  TIERS,
  unwrap,
  type AccessConfig,
  type TestResult,
  type Tier,
} from "./types";

interface Identity {
  role?: string;
}

export const AccessListsPage: React.FC = () => {
  const { t } = useTranslation();
  const { message } = AntdApp.useApp();
  const { data: identity } = useGetIdentity<Identity>();
  const isAdmin = identity?.role === "admin";
  const rbacTooltip = isAdmin ? "" : t("common.adminRoleRequired");

  const [config, setConfig] = useState<AccessConfig>(DEFAULT_CONFIG);
  const [testIp, setTestIp] = useState("");
  const [testHost, setTestHost] = useState("");
  const [testTier, setTestTier] = useState<Tier>("critical");
  const [testResult, setTestResult] = useState<TestResult | null>(null);

  const configQuery = useCustom<AccessConfig>({
    url: "/api/access-lists",
    method: "get",
    queryOptions: { staleTime: 30_000, retry: false },
    errorNotification: false,
  });

  const remoteData = configQuery.result?.data;

  useEffect(() => {
    const c = unwrap<AccessConfig>(remoteData);
    if (!c || typeof c !== "object") return;
    setConfig({
      version: c.version ?? 1,
      dry_run: c.dry_run ?? false,
      ip_whitelist: Array.isArray(c.ip_whitelist) ? c.ip_whitelist : [],
      ip_blacklist: Array.isArray(c.ip_blacklist) ? c.ip_blacklist : [],
      host_whitelist: {
        critical: c.host_whitelist?.critical ?? [],
        high: c.host_whitelist?.high ?? [],
        medium: c.host_whitelist?.medium ?? [],
        catch_all: c.host_whitelist?.catch_all ?? [],
      },
      tier_whitelist_mode: {
        critical: c.tier_whitelist_mode?.critical ?? "blacklist_only",
        high: c.tier_whitelist_mode?.high ?? "blacklist_only",
        medium: c.tier_whitelist_mode?.medium ?? "blacklist_only",
        catch_all: c.tier_whitelist_mode?.catch_all ?? "blacklist_only",
      },
    });
  }, [remoteData]);

  const { mutate: saveConfig, mutation: saveMutation } = useCustomMutation();
  const saving = saveMutation.isPending;

  const onSave = () => {
    saveConfig(
      { url: "/api/access-lists", method: "put", values: config },
      {
        onSuccess: () => {
          message.success(t("accessLists.saved"));
          configQuery.query.refetch();
        },
        onError: (err) => message.error(err.message),
      },
    );
  };

  const testQuery = useCustom<TestResult>({
    url: "/api/access-lists/test",
    method: "get",
    config: { query: { ip: testIp, host: testHost, tier: testTier } },
    queryOptions: { enabled: false, retry: false },
    errorNotification: false,
  });

  const onTest = () => {
    setTestResult(null);
    testQuery.query.refetch();
  };

  const testData = testQuery.result?.data;

  useEffect(() => {
    const d = unwrap<TestResult>(testData);
    if (d && typeof d.verdict === "string") setTestResult(d);
  }, [testData]);

  const setIpWhitelist = (ips: string[]) => setConfig((c) => ({ ...c, ip_whitelist: ips }));
  const setIpBlacklist = (ips: string[]) => setConfig((c) => ({ ...c, ip_blacklist: ips }));
  const setTierHosts = (tier: Tier, hosts: string[]) =>
    setConfig((c) => ({
      ...c,
      host_whitelist: { ...c.host_whitelist, [tier]: hosts },
    }));
  const setTierMode = (tier: Tier, mode: string) =>
    setConfig((c) => ({
      ...c,
      tier_whitelist_mode: { ...c.tier_whitelist_mode, [tier]: mode },
    }));

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <PageHeader
        version={config.version}
        dryRun={config.dry_run}
        saving={saving}
        fetching={configQuery.query.isFetching}
        isAdmin={isAdmin}
        rbacTooltip={rbacTooltip}
        onDryRunChange={(v) => setConfig((c) => ({ ...c, dry_run: v }))}
        onRefresh={() => configQuery.query.refetch()}
        onSave={onSave}
        t={t}
      />

      {configQuery.query.isError && (
        <Alert
          type="warning"
          showIcon
          message={t("accessLists.configUnavailable")}
          description={t("accessLists.configUnavailableDesc")}
        />
      )}

      <Row gutter={[16, 16]}>
        <Col xs={24} lg={12}>
          <IpListCard
            title={t("accessLists.ipWhitelist")}
            value={config.ip_whitelist}
            onChange={setIpWhitelist}
            disabled={!isAdmin}
            color="green"
          />
        </Col>
        <Col xs={24} lg={12}>
          <IpListCard
            title={t("accessLists.ipBlacklist")}
            value={config.ip_blacklist}
            onChange={setIpBlacklist}
            disabled={!isAdmin}
            color="red"
          />
        </Col>
      </Row>

      <Card size="small" title={t("accessLists.tierHostWhitelist")}>
        <Tabs
          items={TIERS.map(({ key, label }) => ({
            key,
            label: (
              <Space size={4}>
                <span>{label}</span>
                <Badge
                  count={config.host_whitelist?.[key]?.length ?? 0}
                  style={{ backgroundColor: "#1677ff" }}
                  overflowCount={9999}
                />
              </Space>
            ),
            children: (
              <TierHostCard
                tier={key}
                hosts={config.host_whitelist?.[key] ?? []}
                mode={config.tier_whitelist_mode?.[key] ?? "blacklist_only"}
                disabled={!isAdmin}
                onHostsChange={setTierHosts}
                onModeChange={setTierMode}
              />
            ),
          }))}
        />
      </Card>

      <DecisionTester
        ip={testIp}
        host={testHost}
        tier={testTier}
        result={testResult}
        isFetching={testQuery.query.isFetching}
        isError={testQuery.query.isError}
        onIpChange={setTestIp}
        onHostChange={setTestHost}
        onTierChange={setTestTier}
        onTest={onTest}
        t={t}
      />
    </Space>
  );
};
