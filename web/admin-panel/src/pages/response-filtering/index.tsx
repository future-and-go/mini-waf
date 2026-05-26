import {
  Alert,
  Button,
  Card,
  Col,
  Form,
  Input,
  InputNumber,
  Radio,
  Row,
  Select,
  Space,
  Switch,
  Tabs,
  Tag,
  Typography,
  App,
} from "antd";
import { FilterOutlined, PlusOutlined, CloseOutlined } from "@ant-design/icons";
import { useCustom, useCustomMutation } from "@refinedev/core";
import { useTranslation } from "react-i18next";
import { useState, useEffect } from "react";

interface ResponseFilterConfig {
  categories: {
    stack_trace: { enabled: boolean; redact: boolean };
    verbose_error: { enabled: boolean; redact: boolean };
    secrets: { enabled: boolean; redact: boolean };
    internal_ip: { enabled: boolean; redact: boolean };
  };
  json_redact_fields: string[];
  max_body_bytes: number;
}

interface HostResponseFilter {
  body_scan_enabled: boolean;
  body_scan_max_body_bytes: number;
  internal_patterns: string[];
  header_blocklist: string[];
  strip_server_header: boolean;
}

interface Host {
  id: number;
  host_code: string;
  hostname: string;
}

interface PanelConfig {
  response_filtering?: ResponseFilterConfig;
}

const CATEGORIES = [
  { key: "stack_trace" as const, label: "Stack Trace" },
  { key: "verbose_error" as const, label: "Verbose Error" },
  { key: "secrets" as const, label: "Secrets" },
  { key: "internal_ip" as const, label: "Internal IP" },
];

const DEFAULT_FILTER_CONFIG: ResponseFilterConfig = {
  categories: {
    stack_trace: { enabled: false, redact: true },
    verbose_error: { enabled: false, redact: true },
    secrets: { enabled: false, redact: true },
    internal_ip: { enabled: false, redact: true },
  },
  json_redact_fields: [],
  max_body_bytes: 65536,
};

// Editable tag input for lists of strings
const TagListInput: React.FC<{
  value?: string[];
  onChange?: (v: string[]) => void;
  placeholder?: string;
  validator?: (v: string) => string | null;
}> = ({ value = [], onChange, placeholder, validator }) => {
  const [input, setInput] = useState("");
  const [error, setError] = useState("");

  const add = () => {
    const trimmed = input.trim();
    if (!trimmed) return;
    if (validator) {
      const err = validator(trimmed);
      if (err) { setError(err); return; }
    }
    setError("");
    if (!value.includes(trimmed)) {
      onChange?.([...value, trimmed]);
    }
    setInput("");
  };

  const remove = (item: string) => onChange?.(value.filter((v) => v !== item));

  return (
    <Space direction="vertical" size={4} style={{ width: "100%" }}>
      <Space.Compact style={{ width: "100%" }}>
        <Input
          value={input}
          onChange={(e) => { setInput(e.target.value); setError(""); }}
          onPressEnter={add}
          placeholder={placeholder}
          style={{ fontFamily: "ui-monospace, monospace" }}
        />
        <Button icon={<PlusOutlined />} onClick={add} />
      </Space.Compact>
      {error && <Alert type="error" message={error} showIcon banner />}
      <Space wrap size={4}>
        {value.map((item) => (
          <Tag
            key={item}
            closable
            onClose={() => remove(item)}
            closeIcon={<CloseOutlined style={{ fontSize: 10 }} />}
            style={{ fontFamily: "ui-monospace, monospace", fontSize: 11 }}
          >
            {item}
          </Tag>
        ))}
      </Space>
    </Space>
  );
};

const GlobalTab: React.FC = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [form] = Form.useForm<ResponseFilterConfig>();
  const [previewBody, setPreviewBody] = useState("");
  const [previewType, setPreviewType] = useState("application/json");
  const [previewResult, setPreviewResult] = useState("");

  const configQuery = useCustom<PanelConfig>({
    url: "/api/panel-config",
    method: "get",
    queryOptions: { staleTime: 30_000 },
    errorNotification: false,
  });

  const { mutate: saveConfig, mutation: saveMutation } = useCustomMutation();
  const { mutate: previewMutate, mutation: previewMutation } = useCustomMutation();

  useEffect(() => {
    const raw = configQuery.result?.data;
    if (!raw) return;
    const cfg = (raw as PanelConfig).response_filtering ?? DEFAULT_FILTER_CONFIG;
    form.setFieldsValue(cfg);
  }, [configQuery.result]);

  const onSave = async () => {
    const vals = await form.validateFields();
    const current = (configQuery.result?.data as PanelConfig) ?? {};
    saveConfig(
      {
        url: "/api/panel-config",
        method: "put",
        values: { ...current, response_filtering: vals },
      },
      {
        onSuccess: () => { message.success(t("responseFilter.saved", { defaultValue: "Settings saved" })); configQuery.query.refetch(); },
        onError: (err) => message.error(err.message),
      },
    );
  };

  const onPreview = () => {
    previewMutate(
      {
        url: "/api/response-filtering/preview",
        method: "post",
        values: { body: previewBody, content_type: previewType },
      },
      {
        onSuccess: (data) => {
          const r = data.data as unknown as { result: string };
          setPreviewResult(typeof r?.result === "string" ? r.result : JSON.stringify(r, null, 2));
        },
        onError: (err) => setPreviewResult(`Error: ${err.message}`),
      },
    );
  };

  if (configQuery.query.isError) {
    return (
      <Alert
        type="error"
        showIcon
        message={t("responseFilter.loadError", { defaultValue: "Failed to load configuration" })}
      />
    );
  }

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Form
        form={form}
        layout="vertical"
        initialValues={DEFAULT_FILTER_CONFIG}
      >
        {/* Category cards */}
        <Row gutter={[12, 12]} style={{ marginBottom: 12 }}>
          {CATEGORIES.map(({ key, label }) => (
            <Col xs={24} sm={12} key={key}>
              <Card size="small" title={label}>
                <Space size="large">
                  <Space>
                    <Form.Item name={["categories", key, "enabled"]} valuePropName="checked" noStyle>
                      <Switch size="small" />
                    </Form.Item>
                    <span style={{ fontSize: 13 }}>{t("common.enabled")}</span>
                  </Space>
                  <Form.Item name={["categories", key, "redact"]} noStyle>
                    <Radio.Group size="small">
                      <Radio.Button value={true}>redact</Radio.Button>
                      <Radio.Button value={false}>block_on_match</Radio.Button>
                    </Radio.Group>
                  </Form.Item>
                </Space>
              </Card>
            </Col>
          ))}
        </Row>

        {/* JSON redact fields */}
        <Card size="small" title={t("responseFilter.jsonRedactFields", { defaultValue: "JSON Redact Fields" })} style={{ marginBottom: 12 }}>
          <Form.Item name="json_redact_fields" noStyle>
            <TagListInput placeholder={t("responseFilter.addField", { defaultValue: "e.g. password" })} />
          </Form.Item>
        </Card>

        {/* Max body bytes */}
        <Card size="small" title={t("responseFilter.maxBodyBytes", { defaultValue: "Max Body Scan Bytes" })} style={{ marginBottom: 12 }}>
          <Form.Item name="max_body_bytes" noStyle>
            <InputNumber
              min={1024}
              max={10_485_760}
              step={1024}
              style={{ width: 200 }}
              addonAfter="bytes"
            />
          </Form.Item>
        </Card>

        <Button type="primary" loading={saveMutation.isPending} onClick={onSave}>
          {t("common.save")}
        </Button>
      </Form>

      {/* Preview widget */}
      <Card size="small" title={t("responseFilter.preview", { defaultValue: "Response Body Preview" })}>
        <Row gutter={[12, 12]}>
          <Col xs={24} md={12}>
            <Space direction="vertical" style={{ width: "100%" }}>
              <Space>
                <Select
                  value={previewType}
                  onChange={setPreviewType}
                  style={{ width: 220 }}
                  options={[
                    { value: "application/json", label: "application/json" },
                    { value: "text/html", label: "text/html" },
                    { value: "text/plain", label: "text/plain" },
                    { value: "application/xml", label: "application/xml" },
                  ]}
                />
                <Button type="primary" loading={previewMutation.isPending} onClick={onPreview}>
                  {t("responseFilter.previewBtn", { defaultValue: "Preview" })}
                </Button>
              </Space>
              <Input.TextArea
                rows={8}
                value={previewBody}
                onChange={(e) => setPreviewBody(e.target.value)}
                placeholder={t("responseFilter.sampleBody", { defaultValue: 'Paste sample response body here…' })}
                style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}
              />
            </Space>
          </Col>
          <Col xs={24} md={12}>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {t("responseFilter.previewResult", { defaultValue: "Filtered result" })}
            </Typography.Text>
            <Input.TextArea
              rows={9}
              value={previewResult}
              readOnly
              style={{ fontFamily: "ui-monospace, monospace", fontSize: 12, marginTop: 4 }}
              placeholder={t("responseFilter.previewPlaceholder", { defaultValue: "Result will appear here after preview" })}
            />
          </Col>
        </Row>
      </Card>
    </Space>
  );
};

const PerHostTab: React.FC = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [selectedHostId, setSelectedHostId] = useState<number | undefined>(undefined);
  const [form] = Form.useForm<HostResponseFilter>();

  const hostsQuery = useCustom<{ data: Host[] }>({
    url: "/api/hosts",
    method: "get",
    queryOptions: { staleTime: 60_000 },
    errorNotification: false,
  });

  const hostFilterQuery = useCustom<HostResponseFilter>({
    url: selectedHostId != null ? `/api/hosts/${selectedHostId}/response-filter` : "",
    method: "get",
    queryOptions: { staleTime: 10_000, enabled: selectedHostId != null },
    errorNotification: false,
  });

  const { mutate: saveFilter, mutation: saveMutation } = useCustomMutation();

  const hosts: Host[] = (() => {
    const raw = hostsQuery.result?.data;
    if (!raw) return [];
    if (Array.isArray(raw)) return raw;
    if (Array.isArray((raw as { data: Host[] }).data)) return (raw as { data: Host[] }).data;
    return [];
  })();

  useEffect(() => {
    if (!hostFilterQuery.result?.data) return;
    const data = hostFilterQuery.result.data as HostResponseFilter;
    form.setFieldsValue(data);
  }, [hostFilterQuery.result]);

  useEffect(() => {
    if (selectedHostId == null) return;
    form.resetFields();
  }, [selectedHostId]);

  const onSave = async () => {
    if (selectedHostId == null) return;
    const vals = await form.validateFields();
    saveFilter(
      {
        url: `/api/hosts/${selectedHostId}/response-filter`,
        method: "put",
        values: vals,
      },
      {
        onSuccess: () => message.success(t("responseFilter.saved", { defaultValue: "Settings saved" })),
        onError: (err) => message.error(err.message),
      },
    );
  };

  const validateRegex = (pattern: string): string | null => {
    try {
      new RegExp(pattern);
      return null;
    } catch (e) {
      return String(e);
    }
  };

  const warnIfAuthorization = (header: string) => {
    if (header.toLowerCase() === "authorization") {
      message.warning(t("responseFilter.authorizationWarning", { defaultValue: "Blocking 'Authorization' may break authenticated requests" }));
    }
    return null;
  };

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Card size="small" title={t("responseFilter.selectHost", { defaultValue: "Select Host" })}>
        <Select
          style={{ width: 300 }}
          placeholder={t("responseFilter.hostPlaceholder", { defaultValue: "Choose a host…" })}
          value={selectedHostId}
          onChange={(v) => setSelectedHostId(v)}
          loading={hostsQuery.query.isLoading}
          options={hosts.map((h) => ({
            value: h.id,
            label: h.hostname ?? h.host_code,
          }))}
          showSearch
          optionFilterProp="label"
        />
      </Card>

      {selectedHostId == null ? (
        <Alert
          type="info"
          showIcon
          message={t("responseFilter.selectHostFirst", { defaultValue: "Select a host to configure per-host response filtering" })}
        />
      ) : hostFilterQuery.query.isError ? (
        <Alert
          type="error"
          showIcon
          message={t("responseFilter.loadError", { defaultValue: "Failed to load host configuration" })}
        />
      ) : (
        <Card
          size="small"
          title={t("responseFilter.perHostSettings", { defaultValue: "Per-Host Settings" })}
          loading={hostFilterQuery.query.isLoading}
        >
          <Form
            form={form}
            layout="vertical"
            initialValues={{
              body_scan_enabled: false,
              body_scan_max_body_bytes: 65536,
              internal_patterns: [],
              header_blocklist: [],
              strip_server_header: false,
            }}
          >
            <Row gutter={[16, 0]}>
              <Col xs={24} sm={8}>
                <Form.Item
                  name="body_scan_enabled"
                  valuePropName="checked"
                  label={t("responseFilter.bodyScanEnabled", { defaultValue: "Body Scan Enabled" })}
                >
                  <Switch />
                </Form.Item>
              </Col>
              <Col xs={24} sm={8}>
                <Form.Item
                  name="strip_server_header"
                  valuePropName="checked"
                  label={t("responseFilter.stripServerHeader", { defaultValue: "Strip Server Header" })}
                >
                  <Switch />
                </Form.Item>
              </Col>
              <Col xs={24} sm={8}>
                <Form.Item
                  name="body_scan_max_body_bytes"
                  label={t("responseFilter.maxBodyBytes", { defaultValue: "Max Body Scan Bytes" })}
                >
                  <InputNumber min={1024} max={10_485_760} step={1024} style={{ width: "100%" }} addonAfter="bytes" />
                </Form.Item>
              </Col>
            </Row>

            <Form.Item
              name="internal_patterns"
              label={t("responseFilter.internalPatterns", { defaultValue: "Internal Patterns (regex)" })}
            >
              <TagListInput
                placeholder={t("responseFilter.addPattern", { defaultValue: "e.g. 192\\.168\\..*" })}
                validator={validateRegex}
              />
            </Form.Item>

            <Form.Item
              name="header_blocklist"
              label={t("responseFilter.headerBlocklist", { defaultValue: "Header Blocklist" })}
            >
              <TagListInput
                placeholder={t("responseFilter.addHeader", { defaultValue: "e.g. X-Powered-By" })}
                validator={warnIfAuthorization}
              />
            </Form.Item>

            <Button type="primary" loading={saveMutation.isPending} onClick={onSave}>
              {t("common.save")}
            </Button>
          </Form>
        </Card>
      )}
    </Space>
  );
};

export const ResponseFilteringPage: React.FC = () => {
  const { t } = useTranslation();

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Space>
        <FilterOutlined style={{ fontSize: 18, color: "#1677ff" }} />
        <Typography.Title level={4} style={{ margin: 0 }}>
          {t("responseFilter.title", { defaultValue: "Response Filtering (FR-033/034/035)" })}
        </Typography.Title>
      </Space>

      <Card size="small">
        <Tabs
          defaultActiveKey="global"
          items={[
            {
              key: "global",
              label: t("responseFilter.tabGlobal", { defaultValue: "Global" }),
              children: <GlobalTab />,
            },
            {
              key: "per-host",
              label: t("responseFilter.tabPerHost", { defaultValue: "Per-Host" }),
              children: <PerHostTab />,
            },
          ]}
        />
      </Card>
    </Space>
  );
};
