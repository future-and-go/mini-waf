import {
  Alert,
  Button,
  Card,
  Drawer,
  Form,
  Input,
  Popconfirm,
  Radio,
  Row,
  Col,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Typography,
  App,
  Modal,
  Divider,
} from "antd";
import type { ColumnsType } from "antd/es/table";
import {
  DeleteOutlined,
  EditOutlined,
  EyeInvisibleOutlined,
  ImportOutlined,
  PlusOutlined,
} from "@ant-design/icons";
import { useCustom, useCustomMutation } from "@refinedev/core";
import { useTranslation } from "react-i18next";
import { useEffect, useState } from "react";

interface SensitivePattern {
  id: number;
  host_code?: string;
  pattern: string;
  pattern_type: "word" | "regex";
  check_request: boolean;
  check_response: boolean;
  action: "block" | "redact" | "log";
  remarks?: string;
  enabled: boolean;
  created_at: string;
}

interface Host {
  id: number;
  host_code: string;
  hostname: string;
}

interface PatternForm {
  host_code?: string;
  pattern: string;
  pattern_type: "word" | "regex";
  check_request: boolean;
  check_response: boolean;
  action: "block" | "redact" | "log";
  remarks?: string;
}

const testPattern = (pattern: string, type: "word" | "regex", sample: string): string[] => {
  if (!pattern || !sample) return [];
  try {
    const re = type === "regex" ? new RegExp(pattern, "g") : new RegExp(pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g");
    const matches: string[] = [];
    let m: RegExpExecArray | null;
    while ((m = re.exec(sample)) !== null) matches.push(m[0]);
    return matches;
  } catch {
    return [];
  }
};

export const SensitivePatternsPage: React.FC = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [editTarget, setEditTarget] = useState<SensitivePattern | null>(null);
  const [hostFilter, setHostFilter] = useState<string | undefined>(undefined);
  const [bulkOpen, setBulkOpen] = useState(false);
  const [bulkText, setBulkText] = useState("");
  const [bulkPreview, setBulkPreview] = useState<string[]>([]);
  const [patternType, setPatternType] = useState<"word" | "regex">("word");
  const [sampleText, setSampleText] = useState("");
  const [regexError, setRegexError] = useState("");
  const [form] = Form.useForm<PatternForm>();

  const patternsQuery = useCustom<{ data: SensitivePattern[]; total: number }>({
    url: "/api/sensitive-patterns",
    method: "get",
    queryOptions: { staleTime: 10_000 },
    errorNotification: false,
  });

  const hostsQuery = useCustom<{ data: Host[] }>({
    url: "/api/hosts",
    method: "get",
    queryOptions: { staleTime: 60_000 },
    errorNotification: false,
  });

  const { mutate: createMutate, mutation: createMutation } = useCustomMutation();
  const { mutate: deleteMutate } = useCustomMutation();
  const { mutate: toggleMutate } = useCustomMutation();

  const patterns: SensitivePattern[] = (() => {
    const raw = patternsQuery.result?.data;
    if (!raw) return [];
    if (Array.isArray(raw)) return raw;
    if (Array.isArray((raw as { data: SensitivePattern[] }).data)) return (raw as { data: SensitivePattern[] }).data;
    return [];
  })();

  const hosts: Host[] = (() => {
    const raw = hostsQuery.result?.data;
    if (!raw) return [];
    if (Array.isArray(raw)) return raw;
    if (Array.isArray((raw as { data: Host[] }).data)) return (raw as { data: Host[] }).data;
    return [];
  })();

  const filtered = hostFilter ? patterns.filter(p => p.host_code === hostFilter) : patterns;

  const validateRegex = (pattern: string, type: "word" | "regex") => {
    if (type !== "regex") { setRegexError(""); return true; }
    try { new RegExp(pattern); setRegexError(""); return true; }
    catch (e: unknown) { setRegexError(String(e)); return false; }
  };

  useEffect(() => {
    const v = form.getFieldValue("pattern");
    if (v) validateRegex(v, patternType);
  }, [patternType]);

  const openCreate = () => {
    setEditTarget(null);
    form.resetFields();
    form.setFieldsValue({ pattern_type: "word", check_request: true, check_response: false, action: "log" });
    setPatternType("word");
    setSampleText("");
    setRegexError("");
    setDrawerOpen(true);
  };

  const openEdit = (row: SensitivePattern) => {
    setEditTarget(row);
    form.setFieldsValue(row);
    setPatternType(row.pattern_type);
    setSampleText("");
    setRegexError("");
    setDrawerOpen(true);
  };

  const handleSubmit = async () => {
    const vals = await form.validateFields();
    if (!validateRegex(vals.pattern, vals.pattern_type)) return;
    if (vals.pattern.length < 3) { message.error(t("sensitive.patternTooShort")); return; }

    createMutate(
      {
        url: editTarget ? `/api/sensitive-patterns/${editTarget.id}` : "/api/sensitive-patterns",
        method: editTarget ? "patch" : "post",
        values: vals,
      },
      {
        onSuccess: () => {
          message.success(t("common.save") + " OK");
          setDrawerOpen(false);
          patternsQuery.query.refetch();
        },
        onError: () => message.error("Failed"),
      }
    );
  };

  const handleDelete = (id: number) => {
    deleteMutate(
      { url: `/api/sensitive-patterns/${id}`, method: "delete", values: {} },
      {
        onSuccess: () => { message.success(t("sensitive.deleted")); patternsQuery.query.refetch(); },
      }
    );
  };

  const handleToggle = (row: SensitivePattern, checked: boolean) => {
    toggleMutate(
      { url: `/api/sensitive-patterns/${row.id}`, method: "patch", values: { enabled: checked } },
      { onSuccess: () => patternsQuery.query.refetch() }
    );
  };

  const parseBulk = (text: string) => {
    const lines = text.split("\n").map(l => l.trim()).filter(l => l.length >= 3);
    setBulkPreview(lines);
  };

  const submitBulk = async () => {
    for (const p of bulkPreview) {
      await new Promise<void>(resolve => {
        createMutate(
          { url: "/api/sensitive-patterns", method: "post", values: { pattern: p, pattern_type: "word", check_request: true, check_response: false, action: "log", enabled: true } },
          { onSuccess: () => resolve(), onError: () => resolve() }
        );
      });
    }
    message.success(t("sensitive.bulkImported", { count: bulkPreview.length }));
    setBulkOpen(false);
    setBulkText("");
    setBulkPreview([]);
    patternsQuery.query.refetch();
  };

  const columns: ColumnsType<SensitivePattern> = [
    {
      title: t("sensitive.host"),
      dataIndex: "host_code",
      width: 130,
      render: v => v ? <Tag>{v}</Tag> : <Tag color="blue">global</Tag>,
    },
    {
      title: t("sensitive.pattern"),
      dataIndex: "pattern",
      render: (v, row) => (
        <Space>
          <Typography.Text code style={{ maxWidth: 200 }} ellipsis>{v}</Typography.Text>
          <Tag color={row.pattern_type === "regex" ? "purple" : "default"}>{row.pattern_type}</Tag>
        </Space>
      ),
    },
    {
      title: t("sensitive.direction"),
      render: (_, row) => (
        <Space>
          {row.check_request && <Tag color="blue">req</Tag>}
          {row.check_response && <Tag color="orange">resp</Tag>}
        </Space>
      ),
      width: 120,
    },
    {
      title: t("sensitive.action"),
      dataIndex: "action",
      width: 90,
      render: v => <Tag color={v === "block" ? "red" : v === "redact" ? "orange" : "default"}>{v}</Tag>,
    },
    {
      title: t("common.enabled"),
      dataIndex: "enabled",
      width: 80,
      render: (v, row) => <Switch checked={v} size="small" onChange={checked => handleToggle(row, checked)} />,
    },
    { title: t("sensitive.remarks"), dataIndex: "remarks", render: v => v ?? "—" },
    {
      title: t("common.actions"),
      width: 100,
      render: (_, row) => (
        <Space>
          <Button size="small" icon={<EditOutlined />} onClick={() => openEdit(row)} />
          <Popconfirm title={t("sensitive.confirmDelete")} onConfirm={() => handleDelete(row.id)} okButtonProps={{ danger: true }}>
            <Button size="small" danger icon={<DeleteOutlined />} />
          </Popconfirm>
        </Space>
      ),
    },
  ];

  const testMatches = testPattern(form.getFieldValue("pattern") ?? "", patternType, sampleText);

  return (
    <>
      <Card
        title={<Space><EyeInvisibleOutlined /><span>{t("sensitive.title")}</span></Space>}
        extra={
          <Space>
            <Select
              style={{ width: 160 }}
              placeholder={t("sensitive.allHosts")}
              allowClear
              value={hostFilter}
              onChange={setHostFilter}
              options={hosts.map(h => ({ value: h.host_code, label: h.hostname ?? h.host_code }))}
            />
            <Button icon={<ImportOutlined />} onClick={() => setBulkOpen(true)}>{t("sensitive.bulkImport")}</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>{t("sensitive.addPattern")}</Button>
          </Space>
        }
        loading={patternsQuery.query.isLoading}
      >
        <Typography.Paragraph type="secondary">{t("sensitive.subtitle")}</Typography.Paragraph>
        <Table
          dataSource={filtered}
          columns={columns}
          rowKey="id"
          size="small"
          pagination={{ pageSize: 20 }}
        />
      </Card>

      {/* Create/Edit drawer */}
      <Drawer
        title={editTarget ? t("sensitive.editPattern") : t("sensitive.addPattern")}
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        width={520}
        footer={
          <Space style={{ justifyContent: "flex-end", width: "100%", display: "flex" }}>
            <Button onClick={() => setDrawerOpen(false)}>{t("common.cancel")}</Button>
            <Button type="primary" loading={createMutation.isPending} onClick={handleSubmit}>{t("common.save")}</Button>
          </Space>
        }
      >
        <Form form={form} layout="vertical">
          <Form.Item name="host_code" label={t("sensitive.host")}>
            <Select
              allowClear
              placeholder="global"
              options={hosts.map(h => ({ value: h.host_code, label: h.hostname ?? h.host_code }))}
            />
          </Form.Item>
          <Row gutter={12}>
            <Col span={16}>
              <Form.Item name="pattern" label={t("sensitive.pattern")} rules={[{ required: true }]}>
                <Input onChange={e => validateRegex(e.target.value, patternType)} />
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item name="pattern_type" label={t("sensitive.patternType")}>
                <Radio.Group onChange={e => setPatternType(e.target.value)}>
                  <Radio.Button value="word">word</Radio.Button>
                  <Radio.Button value="regex">regex</Radio.Button>
                </Radio.Group>
              </Form.Item>
            </Col>
          </Row>
          {regexError && <Alert type="error" message={regexError} style={{ marginBottom: 12 }} />}

          {/* Live test */}
          <Form.Item label={t("sensitive.liveTest")}>
            <Input.TextArea
              rows={3}
              placeholder={t("sensitive.samplePlaceholder")}
              value={sampleText}
              onChange={e => setSampleText(e.target.value)}
            />
          </Form.Item>
          {sampleText && (
            <Alert
              type={testMatches.length > 0 ? "success" : "info"}
              message={testMatches.length > 0
                ? t("sensitive.matchFound", { count: testMatches.length, matches: testMatches.join(", ") })
                : t("sensitive.noMatch")}
              style={{ marginBottom: 12 }}
            />
          )}

          <Divider />
          <Row gutter={12}>
            <Col span={8}>
              <Form.Item name="check_request" valuePropName="checked" label={t("sensitive.checkRequest")}>
                <Switch />
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item name="check_response" valuePropName="checked" label={t("sensitive.checkResponse")}>
                <Switch />
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item name="action" label={t("sensitive.action")}>
                <Select options={[
                  { value: "block", label: "block" },
                  { value: "redact", label: "redact" },
                  { value: "log", label: "log" },
                ]} />
              </Form.Item>
            </Col>
          </Row>
          <Form.Item name="remarks" label={t("sensitive.remarks")}>
            <Input.TextArea rows={2} />
          </Form.Item>
        </Form>
      </Drawer>

      {/* Bulk import modal */}
      <Modal
        title={t("sensitive.bulkImport")}
        open={bulkOpen}
        onOk={submitBulk}
        onCancel={() => { setBulkOpen(false); setBulkText(""); setBulkPreview([]); }}
        okText={t("sensitive.importCount", { count: bulkPreview.length })}
      >
        <Form.Item label={t("sensitive.bulkHint")}>
          <Input.TextArea
            rows={8}
            value={bulkText}
            onChange={e => { setBulkText(e.target.value); parseBulk(e.target.value); }}
            placeholder={"password\ncredit_card\napi_key\n..."}
          />
        </Form.Item>
        {bulkPreview.length > 0 && (
          <Alert type="info" message={t("sensitive.bulkPreview", { count: bulkPreview.length })} />
        )}
      </Modal>
    </>
  );
};
