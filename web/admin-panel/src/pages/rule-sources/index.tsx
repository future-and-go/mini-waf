import {
  Alert,
  Button,
  Card,
  Form,
  Input,
  InputNumber,
  List,
  Modal,
  Popconfirm,
  Select,
  Skeleton,
  Space,
  Tag,
  Typography,
  App,
} from "antd";
import { useCustom, useCustomMutation } from "@refinedev/core";
import { useTranslation } from "react-i18next";
import { useMemo, useState } from "react";
import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";
import type { RegistryRule, RuleSource } from "../../types/api";

dayjs.extend(relativeTime);

interface SourcesResponse {
  sources?: RuleSource[];
}

interface RegistryResponse {
  rules?: RegistryRule[];
}

interface SourceForm {
  name: string;
  // BACKEND-GAP: Verify whether POST /api/rule-sources accepts `type` or `source_type`.
  // Check crates/waf-common/src/config.rs::RuleSourceEntry and
  // crates/waf-api/src/server.rs for the POST route handler.
  // Sending both `type` and `source_type` for forward-compatibility until confirmed.
  type: string;
  url: string;
  format: string;
  updateInterval: number;
}

export const RuleSourcesPage: React.FC = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [open, setOpen] = useState(false);
  const [form] = Form.useForm<SourceForm>();

  const { result, query } = useCustom<SourcesResponse>({
    url: "/api/rule-sources",
    method: "get",
    queryOptions: { staleTime: 30_000 },
  });

  // Fetch registry to compute builtin source counts dynamically
  const { result: registryResult, query: registryQuery } = useCustom<RegistryResponse>({
    url: "/api/rules/registry",
    method: "get",
    queryOptions: { staleTime: 60_000 },
  });

  const { mutate: syncAll, mutation: syncAllMutation } = useCustomMutation();
  const { mutate: syncOne } = useCustomMutation();
  const { mutate: removeOne } = useCustomMutation();
  const { mutate: addSource } = useCustomMutation();
  const refetch = query.refetch;
  const isLoading = query.isLoading;
  const syncing = syncAllMutation.isPending;

  const rawSources = result?.data?.sources;
  const sources = Array.isArray(rawSources) ? rawSources : [];

  // Compute builtin source groups dynamically from registry rules
  const builtinGroups = useMemo(() => {
    const registryRaw = registryResult?.data as RegistryResponse | { data: RegistryResponse } | undefined;
    const normalizedRules: RegistryRule[] = Array.isArray(
      (registryRaw as RegistryResponse)?.rules,
    )
      ? ((registryRaw as RegistryResponse).rules as RegistryRule[])
      : Array.isArray((registryRaw as { data: RegistryResponse })?.data?.rules)
        ? ((registryRaw as { data: RegistryResponse }).data.rules as RegistryRule[])
        : [];

    // Group rules by source, showing only sources not in user-configured list
    const configuredNames = new Set(sources.map((s) => s.name));
    const sourceGroups = new Map<string, number>();
    for (const r of normalizedRules) {
      if (!configuredNames.has(r.source)) {
        sourceGroups.set(r.source, (sourceGroups.get(r.source) ?? 0) + 1);
      }
    }
    return [...sourceGroups.entries()]
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [registryResult, sources]);

  const onSyncAll = () =>
    syncAll(
      { url: "/api/rule-sources/sync", method: "post", values: {} },
      {
        onSuccess: () => { message.success("OK"); refetch(); },
        onError: (err) => message.error(err.message),
      },
    );

  const onSyncOne = (name: string) =>
    syncOne(
      { url: `/api/rule-sources/${name}/sync`, method: "post", values: {} },
      { onSuccess: () => refetch(), onError: (err) => message.error(err.message) },
    );

  const onRemove = (name: string) =>
    removeOne(
      { url: `/api/rule-sources/${name}`, method: "delete", values: {} },
      { onSuccess: () => refetch(), onError: (err) => message.error(err.message) },
    );

  const onAdd = async () => {
    const v = await form.validateFields();
    addSource(
      {
        url: "/api/rule-sources",
        method: "post",
        // Send both field names for compatibility (see BACKEND-GAP above)
        values: {
          name: v.name,
          type: v.type,
          source_type: v.type,
          url: v.url,
          format: v.format,
          update_interval: v.updateInterval,
        },
      },
      {
        onSuccess: () => {
          message.success("OK");
          setOpen(false);
          form.resetFields();
          refetch();
        },
        onError: (err) => message.error(err.message),
      },
    );
  };

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <div>
          <Typography.Title level={4} style={{ margin: 0 }}>
            {t("ruleSources.title")}
          </Typography.Title>
          <Typography.Text type="secondary">{t("ruleSources.subtitle")}</Typography.Text>
        </div>
        <Space>
          <Button onClick={onSyncAll} loading={syncing}>
            {syncing ? t("ruleSources.syncing") : t("ruleSources.syncAll")}
          </Button>
          <Button type="primary" onClick={() => setOpen(true)}>
            {t("ruleSources.addSource")}
          </Button>
        </Space>
      </Space>

      {/* Built-in sources — counts fetched dynamically from registry */}
      <Card size="small" title={t("ruleSources.builtinSources")}>
        {registryQuery.isLoading ? (
          <Skeleton active paragraph={{ rows: 3 }} />
        ) : builtinGroups.length === 0 ? (
          <Typography.Text type="secondary">{t("ruleSources.noSources")}</Typography.Text>
        ) : (
          <List
            size="small"
            dataSource={builtinGroups}
            renderItem={(b) => (
              <List.Item
                actions={[
                  <span key="count" style={{ color: "#8c8c8c", fontSize: 12 }}>
                    {b.count} {t("ruleSources.rules")}
                  </span>,
                  <Tag key="b" color="purple">
                    {t("ruleSources.builtin")}
                  </Tag>,
                ]}
              >
                <List.Item.Meta title={b.name} />
              </List.Item>
            )}
          />
        )}
      </Card>

      {/* User-configured sources */}
      <Card size="small" title={t("ruleSources.configuredSources")} loading={isLoading}>
        {sources.length === 0 ? (
          <Typography.Text type="secondary">{t("ruleSources.noSources")}</Typography.Text>
        ) : (
          <List
            size="small"
            dataSource={sources}
            renderItem={(s) => (
              <List.Item
                actions={[
                  <Tag key="fmt" color="blue">{s.format}</Tag>,
                  <span key="up" style={{ fontSize: 11, color: "#bfbfbf" }}>
                    {s.lastUpdated
                      ? dayjs(s.lastUpdated).fromNow()
                      : t("ruleSources.neverSynced")}
                  </span>,
                  <Button key="s" size="small" type="link" onClick={() => onSyncOne(s.name)}>
                    {t("common.sync")}
                  </Button>,
                  <Popconfirm
                    key="r"
                    title={t("ruleSources.confirmRemove", { name: s.name })}
                    onConfirm={() => onRemove(s.name)}
                  >
                    <Button size="small" type="link" danger>
                      {t("common.remove")}
                    </Button>
                  </Popconfirm>,
                ]}
              >
                <List.Item.Meta
                  title={s.name}
                  description={
                    <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 11 }}>
                      {s.url ?? s.path}
                    </span>
                  }
                />
                {s.error && (
                  <Alert
                    type="error"
                    showIcon
                    message={`${t("ruleSources.error")}${s.error}`}
                    style={{ marginTop: 8, width: "100%" }}
                  />
                )}
              </List.Item>
            )}
          />
        )}
      </Card>

      <Modal
        title={t("ruleSources.addSourceTitle")}
        open={open}
        onCancel={() => setOpen(false)}
        onOk={() => void onAdd()}
        okText={t("ruleSources.addSource")}
        cancelText={t("common.cancel")}
        destroyOnClose
      >
        <Form
          form={form}
          layout="vertical"
          initialValues={{ type: "remote_url", format: "yaml", updateInterval: 86400 }}
        >
          <Form.Item name="name" label={t("ruleSources.sourceName")} rules={[{ required: true }]}>
            <Input placeholder="my-rules" />
          </Form.Item>
          <Form.Item name="type" label={t("ruleSources.sourceType")}>
            <Select
              options={[
                { value: "remote_url", label: t("ruleSources.remoteUrl") },
                { value: "local_dir", label: t("ruleSources.localDir") },
                { value: "local_file", label: t("ruleSources.localFile") },
              ]}
            />
          </Form.Item>
          <Form.Item name="url" label={t("ruleSources.url")} rules={[{ required: true }]}>
            <Input placeholder="https://example.com/rules.yaml" />
          </Form.Item>
          <Form.Item name="format" label={t("common.format")}>
            <Select
              options={[
                { value: "yaml", label: "YAML" },
                { value: "json", label: "JSON" },
                { value: "modsec", label: "ModSecurity" },
              ]}
            />
          </Form.Item>
          <Form.Item name="updateInterval" label={t("ruleSources.updateInterval")}>
            <InputNumber min={60} style={{ width: "100%" }} />
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  );
};
