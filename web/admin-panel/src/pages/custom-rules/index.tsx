import {
  Card,
  Button,
  Space,
  Table,
  Tag,
  Modal,
  Form,
  Input,
  InputNumber,
  Select,
  Switch,
  App,
  Typography,
  Popconfirm,
} from "antd";
import { PlusOutlined } from "@ant-design/icons";
import { useTable, useCreate, useDelete } from "@refinedev/core";
import type { ColumnsType } from "antd/es/table";
import { useTranslation } from "react-i18next";
import { useState } from "react";
import type { CustomRule } from "../../types/api";

interface CustomRuleForm {
  name: string;
  host_code: string;
  priority: number;
  action: string;
  enabled: boolean;
  script: string;
}

export const CustomRulesPage: React.FC = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [form] = Form.useForm<CustomRuleForm>();
  const [open, setOpen] = useState(false);

  const { tableQuery, result } = useTable<CustomRule>({
    resource: "custom-rules",
    pagination: { mode: "off" },
    queryOptions: { staleTime: 30_000 },
  });
  const { mutate: create, mutation: createMutation } = useCreate();
  const { mutate: del } = useDelete();
  const creating = createMutation.isPending;

  const data = Array.isArray(result?.data) ? result.data : [];

  const onSubmit = async () => {
    const values = await form.validateFields();
    create(
      {
        resource: "custom-rules",
        values: { ...values, conditions: [] },
        successNotification: false,
      },
      {
        onSuccess: () => {
          message.success("OK");
          setOpen(false);
          form.resetFields();
          tableQuery.refetch();
        },
        onError: (err) => message.error(err.message),
      },
    );
  };

  const onDel = (id: string) =>
    del(
      { resource: "custom-rules", id, successNotification: false },
      {
        onSuccess: () => {
          message.success("OK");
          tableQuery.refetch();
        },
        onError: (err) => message.error(err.message),
      },
    );

  const columns: ColumnsType<CustomRule> = [
    { title: t("common.name"), dataIndex: "name", render: (v) => <strong>{v}</strong> },
    {
      title: t("rules.host"),
      dataIndex: "host_code",
      render: (v) => <span style={{ fontFamily: "ui-monospace, monospace", color: "#8c8c8c" }}>{v}</span>,
    },
    { title: t("rules.priority"), dataIndex: "priority", width: 100 },
    {
      title: t("security.action"),
      dataIndex: "action",
      width: 100,
      render: (v: string) => <Tag color={v === "block" ? "red" : "blue"}>{v}</Tag>,
    },
    {
      title: t("common.enabled"),
      dataIndex: "enabled",
      width: 90,
      render: (v: boolean) => <Tag color={v ? "green" : "default"}>{v ? t("common.yes") : t("common.no")}</Tag>,
    },
    {
      title: "",
      key: "ops",
      width: 80,
      render: (_v, r) => (
        <Popconfirm title={t("rules.confirmDelete")} onConfirm={() => onDel(r.id)}>
          <Button type="link" danger size="small">
            {t("common.delete")}
          </Button>
        </Popconfirm>
      ),
    },
  ];

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <Typography.Title level={4} style={{ margin: 0 }}>
          {t("nav.customRules")}
        </Typography.Title>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setOpen(true)}>
          {t("rules.newRule")}
        </Button>
      </Space>

      <Card size="small">
        <Table
          rowKey="id"
          size="small"
          dataSource={data}
          columns={columns}
          loading={tableQuery.isLoading}
          pagination={false}
          locale={{ emptyText: t("rules.noCustomRules") }}
        />
      </Card>

      <Modal
        title={t("rules.createRule")}
        open={open}
        onCancel={() => setOpen(false)}
        onOk={onSubmit}
        confirmLoading={creating}
        width={640}
        okText={t("common.create")}
        cancelText={t("common.cancel")}
        destroyOnClose
      >
        <Form
          form={form}
          layout="vertical"
          initialValues={{ host_code: "*", priority: 100, action: "block", enabled: true }}
        >
          <Space.Compact style={{ width: "100%" }}>
            <Form.Item name="name" label={t("common.name")} rules={[{ required: true }]} style={{ flex: 2 }}>
              <Input />
            </Form.Item>
            <Form.Item name="host_code" label={t("rules.host")} style={{ flex: 1 }}>
              <Input />
            </Form.Item>
          </Space.Compact>
          <Space.Compact style={{ width: "100%" }}>
            <Form.Item name="priority" label={t("rules.priority")} style={{ flex: 1 }}>
              <InputNumber min={1} max={1000} style={{ width: "100%" }} />
            </Form.Item>
            <Form.Item name="action" label={t("security.action")} style={{ flex: 1 }}>
              <Select
                options={[
                  { value: "block", label: t("security.block") },
                  { value: "allow", label: t("security.allow") },
                  { value: "log", label: t("botManagement.logOnly") },
                ]}
              />
            </Form.Item>
            <Form.Item name="enabled" label={t("common.enabled")} valuePropName="checked" style={{ width: 110 }}>
              <Switch />
            </Form.Item>
          </Space.Compact>
          <Form.Item name="script" label={t("rules.script")}>
            <Input.TextArea
              rows={6}
              placeholder={"// Rhai script\n// request.ip, request.path, request.method, request.headers"}
              style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}
            />
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  );
};
