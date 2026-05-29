import { Alert, App as AntdApp, Button, Card, Form, Space, Typography, Tooltip } from "antd";
import { ReloadOutlined, SaveOutlined, ThunderboltOutlined } from "@ant-design/icons";
import { useCustom, useCustomMutation, useGetIdentity } from "@refinedev/core";
import { useTranslation } from "react-i18next";
import { useEffect, useMemo, useState } from "react";
import { MetricsCards } from "./components/metrics-cards";
import { ConfigForm } from "./components/config-form";
import { BanTable } from "./components/ban-table";
import { DEFAULT_CONFIG, unwrap, type BanEntry, type DdosConfig, type DdosMetrics } from "./types";

interface Identity {
  role?: string;
}

const REFRESH_INTERVAL = 5_000;

export const DdosProtectionPage: React.FC = () => {
  const { t } = useTranslation();
  const { message } = AntdApp.useApp();
  const { data: identity } = useGetIdentity<Identity>();
  const isAdmin = identity?.role === "admin";
  const rbacTooltip = isAdmin ? "" : t("common.adminRoleRequired");

  const [config, setConfig] = useState<DdosConfig>(DEFAULT_CONFIG);
  const [endpointMissing, setEndpointMissing] = useState(false);
  const [ipFilter, setIpFilter] = useState("");
  const [form] = Form.useForm<DdosConfig>();

  const { result: metricsResult, query: metricsQuery } = useCustom<DdosMetrics>({
    url: "/api/ddos/metrics",
    method: "get",
    queryOptions: { refetchInterval: REFRESH_INTERVAL, staleTime: 0, retry: false },
    errorNotification: false,
  });

  useEffect(() => {
    if (metricsQuery.isError) setEndpointMissing(true);
  }, [metricsQuery.isError]);

  const metrics = unwrap<DdosMetrics>(metricsResult?.data);

  const { result: configResult, query: configQuery } = useCustom<DdosConfig>({
    url: "/api/ddos/config",
    method: "get",
    queryOptions: { retry: false },
    errorNotification: false,
  });

  useEffect(() => {
    const loaded = unwrap<DdosConfig>(configResult?.data);
    if (loaded?.enabled !== undefined) {
      setConfig(loaded);
      form.setFieldsValue({
        ...loaded,
        ban_durations_secs: loaded.ban_durations_secs ?? [60, 300, 3600],
      });
      setEndpointMissing(false);
    }
  }, [configResult, form]);

  useEffect(() => {
    if (configQuery.isError) setEndpointMissing(true);
  }, [configQuery.isError]);

  const { result: banResult, query: banQuery } = useCustom<BanEntry[]>({
    url: "/api/ddos/ban-table",
    method: "get",
    queryOptions: { refetchInterval: REFRESH_INTERVAL, staleTime: 0, retry: false },
    errorNotification: false,
  });

  const rawBans = useMemo<BanEntry[]>(() => {
    const u = unwrap<BanEntry[]>(banResult?.data);
    return Array.isArray(u) ? u : [];
  }, [banResult]);

  const filteredBans = useMemo(
    () => (ipFilter ? rawBans.filter((b) => b.ip.includes(ipFilter)) : rawBans),
    [rawBans, ipFilter],
  );

  const { mutate: unbanIp } = useCustomMutation();
  const onUnban = (ip: string) => {
    unbanIp(
      { url: `/api/ddos/ban-table/${encodeURIComponent(ip)}`, method: "delete", values: {} },
      {
        onSuccess: () => {
          message.success(t("ddos.unbanned", { ip }));
          banQuery.refetch();
        },
        onError: (err) => message.error(err.message),
      },
    );
  };

  const { mutate: saveConfig, mutation: saveMutation } = useCustomMutation();
  const saving = saveMutation.isPending;

  const onSave = async () => {
    const values = await form.validateFields();
    saveConfig(
      { url: "/api/ddos/config", method: "put", values },
      {
        onSuccess: () => message.success(t("ddos.saved")),
        onError: (err) => message.error(err.message),
      },
    );
  };

  const storeBackend = Form.useWatch("store", form);
  const currentBackend = storeBackend?.backend ?? config.store.backend;

  const onRefresh = () => {
    configQuery.refetch();
    metricsQuery.refetch();
    banQuery.refetch();
  };

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <div>
          <Typography.Title level={4} style={{ margin: 0 }}>
            {t("ddos.title")}
          </Typography.Title>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {t("ddos.subtitle")}
          </Typography.Text>
        </div>
        <Space>
          <Button
            icon={<ReloadOutlined spin={configQuery.isLoading || metricsQuery.isLoading} />}
            onClick={onRefresh}
          >
            {t("common.refresh")}
          </Button>
          <Tooltip title={rbacTooltip}>
            <Button
              type="primary"
              icon={<SaveOutlined />}
              loading={saving}
              onClick={onSave}
              disabled={endpointMissing || !isAdmin}
            >
              {t("common.save")}
            </Button>
          </Tooltip>
        </Space>
      </Space>

      {endpointMissing && (
        <Alert
          type="warning"
          showIcon
          message={t("ddos.endpointMissing")}
          description={t("ddos.endpointMissingDesc")}
        />
      )}

      <MetricsCards metrics={metrics} loading={metricsQuery.isLoading} t={t} />

      <Card
        size="small"
        title={
          <Space size={6}>
            <ThunderboltOutlined style={{ color: "#1677ff" }} />
            <span>{t("ddos.configuration")}</span>
          </Space>
        }
      >
        <ConfigForm form={form} currentBackend={currentBackend} disabled={!isAdmin} t={t} />
      </Card>

      <BanTable
        bans={filteredBans}
        loading={banQuery.isLoading}
        fetching={banQuery.isFetching}
        ipFilter={ipFilter}
        isAdmin={isAdmin}
        rbacTooltip={rbacTooltip}
        onIpFilter={setIpFilter}
        onRefetch={() => banQuery.refetch()}
        onUnban={onUnban}
        t={t}
      />
    </Space>
  );
};
