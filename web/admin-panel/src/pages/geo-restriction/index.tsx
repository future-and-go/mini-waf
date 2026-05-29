import {
  Alert,
  Button,
  Card,
  Col,
  Drawer,
  Form,
  Input,
  Popconfirm,
  Row,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Typography,
  App,
} from "antd";
import { GlobalOutlined, SearchOutlined, DeleteOutlined, PlusOutlined } from "@ant-design/icons";
import { useCustom, useCustomMutation } from "@refinedev/core";
import type { ColumnsType } from "antd/es/table";
import { useTranslation } from "react-i18next";
import { useState, useMemo } from "react";
import { KpiCard } from "../../components/kpi-card";

interface GeoRule {
  id: number;
  iso_code: string;
  country_name?: string;
  action: "block" | "challenge" | "log" | "allow";
  scope: "global" | string;
  enabled: boolean;
  created_at?: string;
}

interface LookupResult {
  iso_code: string;
  country_name: string;
  isp?: string;
}

interface GeoStat {
  iso_code: string;
  country_name?: string;
  count: number;
}

interface AddForm {
  iso_code: string;
  action: "block" | "challenge" | "log" | "allow";
  scope: string;
}

const COUNTRY_MAP: Record<string, { name: string; flag: string }> = {
  CN: { name: "China", flag: "🇨🇳" },
  US: { name: "United States", flag: "🇺🇸" },
  RU: { name: "Russia", flag: "🇷🇺" },
  DE: { name: "Germany", flag: "🇩🇪" },
  FR: { name: "France", flag: "🇫🇷" },
  GB: { name: "United Kingdom", flag: "🇬🇧" },
  IN: { name: "India", flag: "🇮🇳" },
  BR: { name: "Brazil", flag: "🇧🇷" },
  JP: { name: "Japan", flag: "🇯🇵" },
  KR: { name: "South Korea", flag: "🇰🇷" },
  VN: { name: "Vietnam", flag: "🇻🇳" },
  TH: { name: "Thailand", flag: "🇹🇭" },
  TW: { name: "Taiwan", flag: "🇹🇼" },
  HK: { name: "Hong Kong", flag: "🇭🇰" },
  SG: { name: "Singapore", flag: "🇸🇬" },
  AU: { name: "Australia", flag: "🇦🇺" },
  CA: { name: "Canada", flag: "🇨🇦" },
  NL: { name: "Netherlands", flag: "🇳🇱" },
  SE: { name: "Sweden", flag: "🇸🇪" },
  NO: { name: "Norway", flag: "🇳🇴" },
  PL: { name: "Poland", flag: "🇵🇱" },
  UA: { name: "Ukraine", flag: "🇺🇦" },
  IR: { name: "Iran", flag: "🇮🇷" },
  KP: { name: "North Korea", flag: "🇰🇵" },
  PK: { name: "Pakistan", flag: "🇵🇰" },
  ID: { name: "Indonesia", flag: "🇮🇩" },
  NG: { name: "Nigeria", flag: "🇳🇬" },
  EG: { name: "Egypt", flag: "🇪🇬" },
  ZA: { name: "South Africa", flag: "🇿🇦" },
  MX: { name: "Mexico", flag: "🇲🇽" },
};

const countryLabel = (iso: string, name?: string) => {
  const entry = COUNTRY_MAP[iso];
  const flag = entry?.flag ?? "🏳";
  const label = name ?? entry?.name ?? iso;
  return `${flag} ${label}`;
};

const ACTION_OPTIONS = [
  { value: "block", label: "block" },
  { value: "challenge", label: "challenge" },
  { value: "log", label: "log" },
  { value: "allow", label: "allow" },
];


export const GeoRestrictionPage: React.FC = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();

  const [actionFilter, setActionFilter] = useState<string | undefined>(undefined);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [lookupIp, setLookupIp] = useState("");
  const [lookupResult, setLookupResult] = useState<LookupResult | null>(null);
  const [lookupError, setLookupError] = useState("");
  const [addForm] = Form.useForm<AddForm>();

  const rulesQuery = useCustom<GeoRule[]>({
    url: "/api/geoip/rules",
    method: "get",
    queryOptions: { staleTime: 30_000 },
    errorNotification: false,
  });

  const statsQuery = useCustom<GeoStat[]>({
    url: "/api/stats/geo",
    method: "get",
    queryOptions: { staleTime: 60_000 },
    errorNotification: false,
  });

  const { mutate: addRule, mutation: addMutation } = useCustomMutation();
  const { mutate: deleteRule } = useCustomMutation();
  const { mutate: toggleRule } = useCustomMutation();
  const { mutate: lookupMutate } = useCustomMutation();

  const rules: GeoRule[] = (() => {
    const raw = rulesQuery.result?.data;
    if (!raw) return [];
    if (Array.isArray(raw)) return raw;
    if (Array.isArray((raw as { data: GeoRule[] }).data)) return (raw as { data: GeoRule[] }).data;
    return [];
  })();

  const stats: GeoStat[] = (() => {
    const raw = statsQuery.result?.data;
    if (!raw) return [];
    if (Array.isArray(raw)) return raw;
    if (Array.isArray((raw as { data: GeoStat[] }).data)) return (raw as { data: GeoStat[] }).data;
    return [];
  })();

  const filtered = useMemo(
    () => (actionFilter ? rules.filter((r) => r.action === actionFilter) : rules),
    [rules, actionFilter],
  );

  const refetch = rulesQuery.query.refetch;

  const onToggle = (rule: GeoRule, checked: boolean) => {
    toggleRule(
      { url: `/api/geoip/rules/${rule.id}`, method: "patch", values: { enabled: checked } },
      { onSuccess: () => refetch(), onError: (err) => message.error(err.message) },
    );
  };

  const onDelete = (id: number) => {
    deleteRule(
      { url: `/api/geoip/rules/${id}`, method: "delete", values: {} },
      {
        onSuccess: () => { message.success(t("geo.deleted")); refetch(); },
        onError: (err) => message.error(err.message),
      },
    );
  };

  const onChangeAction = (rule: GeoRule, action: string) => {
    toggleRule(
      { url: `/api/geoip/rules/${rule.id}`, method: "patch", values: { action } },
      { onSuccess: () => refetch(), onError: (err) => message.error(err.message) },
    );
  };

  const onAddRule = async () => {
    const vals = await addForm.validateFields();
    addRule(
      { url: "/api/geoip/rules", method: "post", values: vals },
      {
        onSuccess: () => {
          message.success(t("geo.added"));
          setDrawerOpen(false);
          addForm.resetFields();
          refetch();
        },
        onError: (err) => message.error(err.message),
      },
    );
  };

  const onLookup = () => {
    if (!lookupIp.trim()) return;
    setLookupError("");
    setLookupResult(null);
    lookupMutate(
      { url: `/api/geoip/lookup`, method: "post", values: { ip: lookupIp.trim() } },
      {
        onSuccess: (data) => {
          const r = data.data as unknown as LookupResult;
          setLookupResult(r);
        },
        onError: (err) => setLookupError(err.message),
      },
    );
  };

  const onBlockFromLookup = () => {
    if (!lookupResult) return;
    addForm.setFieldsValue({ iso_code: lookupResult.iso_code, action: "block", scope: "global" });
    setDrawerOpen(true);
  };

  const columns: ColumnsType<GeoRule> = [
    {
      title: t("geo.country"),
      key: "country",
      width: 200,
      render: (_, r) => (
        <span style={{ fontWeight: 500 }}>
          {countryLabel(r.iso_code, r.country_name)}
          <Tag style={{ marginLeft: 8, fontSize: 11 }}>{r.iso_code}</Tag>
        </span>
      ),
    },
    {
      title: t("geo.countryName"),
      key: "name",
      render: (_, r) => r.country_name ?? COUNTRY_MAP[r.iso_code]?.name ?? r.iso_code,
    },
    {
      title: t("geo.action"),
      dataIndex: "action",
      width: 170,
      render: (v, r) => (
        <Select
          size="small"
          value={v}
          style={{ width: 130 }}
          options={ACTION_OPTIONS}
          onChange={(val) => onChangeAction(r, val)}
        />
      ),
    },
    {
      title: t("geo.scope"),
      dataIndex: "scope",
      width: 120,
      render: (v) =>
        v === "global" ? (
          <Tag color="blue">global</Tag>
        ) : (
          <Tag>{v}</Tag>
        ),
    },
    {
      title: t("common.enabled"),
      dataIndex: "enabled",
      width: 80,
      render: (v, r) => (
        <Switch size="small" checked={v} onChange={(checked) => onToggle(r, checked)} />
      ),
    },
    {
      title: t("common.actions"),
      width: 80,
      render: (_, r) => (
        <Popconfirm
          title={t("geo.confirmDelete")}
          onConfirm={() => onDelete(r.id)}
          okButtonProps={{ danger: true }}
        >
          <Button size="small" danger icon={<DeleteOutlined />} />
        </Popconfirm>
      ),
    },
  ];

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <div>
          <Typography.Title level={4} style={{ margin: 0 }}>
            {t("geo.title", { defaultValue: "Geo Restriction (FR-041)" })}
          </Typography.Title>
          <Typography.Text type="secondary">{t("geo.subtitle", { defaultValue: "Block or challenge requests by country via GeoIP" })}</Typography.Text>
        </div>
        <Space>
          <Select
            style={{ width: 160 }}
            placeholder={t("geo.filterAll", { defaultValue: "All actions" })}
            allowClear
            value={actionFilter}
            onChange={setActionFilter}
            options={[
              { value: "block", label: "block" },
              { value: "challenge", label: "challenge" },
              { value: "log", label: "log" },
              { value: "allow", label: "allow" },
            ]}
          />
          <Button type="primary" icon={<PlusOutlined />} onClick={() => { addForm.resetFields(); setDrawerOpen(true); }}>
            {t("geo.addCountry", { defaultValue: "Add country" })}
          </Button>
        </Space>
      </Space>

      <Row gutter={[12, 12]}>
        <Col xs={24} lg={16}>
          <Card
            size="small"
            title={t("geo.countryRules", { defaultValue: "Country Rules" })}
            loading={rulesQuery.query.isLoading}
          >
            {rulesQuery.query.isError && (
              <Alert
                type="error"
                showIcon
                message={t("geo.loadError", { defaultValue: "Failed to load geo rules" })}
                style={{ marginBottom: 12 }}
              />
            )}
            <Table<GeoRule>
              rowKey="id"
              size="small"
              dataSource={filtered}
              columns={columns}
              pagination={{ pageSize: 20, size: "small" }}
              locale={{ emptyText: t("geo.noRules", { defaultValue: "No country rules configured" }) }}
              scroll={{ x: 700 }}
            />
          </Card>
        </Col>

        <Col xs={24} lg={8}>
          <Space direction="vertical" size="middle" style={{ width: "100%" }}>
            <Card size="small" title={t("geo.lookup", { defaultValue: "IP Lookup" })}>
              <Space.Compact style={{ width: "100%", marginBottom: 12 }}>
                <Input
                  value={lookupIp}
                  onChange={(e) => setLookupIp(e.target.value)}
                  onPressEnter={onLookup}
                  placeholder="1.2.3.4"
                />
                <Button
                  type="primary"
                  icon={<SearchOutlined />}
                  loading={false}
                  onClick={onLookup}
                >
                  {t("geo.lookup", { defaultValue: "Lookup" })}
                </Button>
              </Space.Compact>

              {lookupError && (
                <Alert type="error" showIcon message={lookupError} style={{ marginBottom: 8 }} />
              )}

              {lookupResult && (
                <Space direction="vertical" size={8} style={{ width: "100%" }}>
                  <div style={{ fontSize: 28, lineHeight: 1 }}>
                    {COUNTRY_MAP[lookupResult.iso_code]?.flag ?? "🏳"}
                  </div>
                  <div>
                    <Tag>{lookupResult.iso_code}</Tag>
                    <strong>{lookupResult.country_name}</strong>
                  </div>
                  {lookupResult.isp && (
                    <div style={{ color: "#8c8c8c", fontSize: 12 }}>ISP: {lookupResult.isp}</div>
                  )}
                  <Button
                    danger
                    size="small"
                    onClick={onBlockFromLookup}
                    icon={<DeleteOutlined />}
                  >
                    {t("geo.blockThisCountry", { defaultValue: "Block this country" })}
                  </Button>
                </Space>
              )}
            </Card>

            <Card
              size="small"
              title={t("geo.topBlocked", { defaultValue: "Top Blocked Countries (24h)" })}
              loading={statsQuery.query.isLoading}
            >
              {statsQuery.query.isError ? (
                <Alert type="warning" showIcon message={t("geo.statsUnavailable", { defaultValue: "Stats unavailable" })} />
              ) : stats.length === 0 ? (
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  {t("geo.noStats", { defaultValue: "No data" })}
                </Typography.Text>
              ) : (
                <Space direction="vertical" size={6} style={{ width: "100%" }}>
                  {stats.slice(0, 5).map((s, i) => (
                    <div key={s.iso_code} style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <span>
                        <span style={{ color: "#8c8c8c", marginRight: 6, fontSize: 11 }}>#{i + 1}</span>
                        {countryLabel(s.iso_code, s.country_name)}
                      </span>
                      <Tag color="red">{s.count.toLocaleString()}</Tag>
                    </div>
                  ))}
                </Space>
              )}
            </Card>

            <KpiCard
              label={t("geo.totalRules", { defaultValue: "Total rules" })}
              value={rules.length}
              icon={GlobalOutlined}
              color="blue"
              loading={rulesQuery.query.isLoading}
            />
          </Space>
        </Col>
      </Row>

      <Drawer
        title={t("geo.addCountry", { defaultValue: "Add Country Rule" })}
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        width={420}
        footer={
          <Space style={{ justifyContent: "flex-end", width: "100%", display: "flex" }}>
            <Button onClick={() => setDrawerOpen(false)}>{t("common.cancel")}</Button>
            <Button type="primary" loading={addMutation.isPending} onClick={onAddRule}>
              {t("common.save")}
            </Button>
          </Space>
        }
        destroyOnClose
      >
        <Form form={addForm} layout="vertical" initialValues={{ action: "block", scope: "global" }}>
          <Form.Item
            name="iso_code"
            label={t("geo.country", { defaultValue: "Country" })}
            rules={[{ required: true }]}
          >
            <Select
              showSearch
              placeholder={t("geo.selectCountry", { defaultValue: "Select country" })}
              optionFilterProp="label"
              options={Object.entries(COUNTRY_MAP).map(([iso, { name, flag }]) => ({
                value: iso,
                label: `${flag} ${name} (${iso})`,
              }))}
            />
          </Form.Item>
          <Form.Item
            name="action"
            label={t("geo.action", { defaultValue: "Action" })}
            rules={[{ required: true }]}
          >
            <Select options={ACTION_OPTIONS} />
          </Form.Item>
          <Form.Item
            name="scope"
            label={t("geo.scope", { defaultValue: "Scope" })}
            rules={[{ required: true }]}
          >
            <Select
              options={[
                { value: "global", label: "global" },
                { value: "host", label: "host" },
              ]}
            />
          </Form.Item>
        </Form>
      </Drawer>
    </Space>
  );
};
