import { Form, Input, Button, Card, Typography, Alert } from "antd";
import { UserOutlined, LockOutlined } from "@ant-design/icons";
import { useLogin } from "@refinedev/core";
import { useTranslation } from "react-i18next";
import { useState } from "react";

interface LoginVars {
  username: string;
  password: string;
}

export const LoginPage: React.FC = () => {
  const { t } = useTranslation();
  // useLogin keeps the flat TanStack Query mutation shape in v5
  // (no `mutation` wrapper like data mutations).
  const { mutate: login, isPending: isLoading } = useLogin<LoginVars>();
  const [error, setError] = useState<string | null>(null);

  const onFinish = (values: LoginVars) => {
    setError(null);
    login(values, {
      // Refine v5 auth provider returns `{ success: false, error }` on soft
      // failures (e.g. wrong password). That is delivered via onSuccess, not
      // onError — so handle both paths.
      onSuccess: (data) => {
        if (!data?.success) {
          setError(data?.error?.message ?? t("auth.invalidCredentials"));
        }
      },
      onError: (err) => {
        setError(err.message ?? t("auth.invalidCredentials"));
      },
    });
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "linear-gradient(135deg, #1f1f1f 0%, #141414 100%)",
        padding: 16,
      }}
    >
      <Card style={{ width: 380 }}>
        <div style={{ textAlign: "center", marginBottom: 24 }}>
          <Typography.Title level={3} style={{ marginBottom: 4 }}>
            {t("auth.loginTitle")}
          </Typography.Title>
          <Typography.Text type="secondary">{t("auth.loginSubtitle")}</Typography.Text>
        </div>

        <Form layout="vertical" onFinish={onFinish} initialValues={{ username: "admin" }}>
          <Form.Item
            name="username"
            label={t("auth.username")}
            rules={[{ required: true }]}
          >
            <Input prefix={<UserOutlined />} placeholder="admin" autoComplete="username" />
          </Form.Item>

          <Form.Item
            name="password"
            label={t("auth.password")}
            rules={[{ required: true }]}
          >
            <Input.Password prefix={<LockOutlined />} placeholder="••••••••" autoComplete="current-password" />
          </Form.Item>

          {error && <Alert type="error" message={error} style={{ marginBottom: 16 }} showIcon />}

          <Button type="primary" htmlType="submit" block loading={isLoading}>
            {isLoading ? t("auth.signingIn") : t("auth.loginButton")}
          </Button>
        </Form>
      </Card>
    </div>
  );
};
