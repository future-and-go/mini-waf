import { Card, Space, Button, InputNumber, Typography, Alert, App } from "antd";
import { CopyOutlined, WarningOutlined } from "@ant-design/icons";
import { useCustom, useCustomMutation } from "@refinedev/core";
import { useTranslation } from "react-i18next";
import { useState } from "react";

interface TokenResponse {
  token: string;
}

export const ClusterTokensPage: React.FC = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();

  // Probe cluster availability via status; treat 404 as "cluster mode off".
  const { query: statusQuery } = useCustom({
    url: "/api/cluster/status",
    method: "get",
    queryOptions: { staleTime: 60_000 },
  });
  const disabled = (statusQuery.error as { statusCode?: number } | null)?.statusCode === 404;

  const [ttlHours, setTtlHours] = useState(1);
  const [token, setToken] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");

  const { mutate: gen, mutation: genMutation } = useCustomMutation<TokenResponse>();
  const generating = genMutation.isPending;

  const onGenerate = () => {
    setToken(null);
    setErrorMsg("");
    gen(
      {
        url: "/api/cluster/token",
        method: "post",
        values: { ttl_ms: ttlHours * 3_600_000 },
      },
      {
        onSuccess: (resp) => setToken(resp.data.token),
        onError: (err) => {
          setErrorMsg(err.message?.includes("CA key not available") ? t("cluster.tokenMainOnly") : err.message);
        },
      },
    );
  };

  const onCopy = async () => {
    if (!token) return;
    try {
      await navigator.clipboard.writeText(token);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      message.error("Copy failed");
    }
  };

  if (disabled) {
    return <Alert type="warning" icon={<WarningOutlined />} showIcon message={t("cluster.clusterDisabled")} />;
  }

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <div>
        <Typography.Title level={4} style={{ margin: 0 }}>
          {t("cluster.tokenTitle")}
        </Typography.Title>
        <Typography.Text type="secondary">{t("cluster.tokenSubtitle")}</Typography.Text>
      </div>

      <Card size="small" title={t("cluster.generateToken")}>
        <Space align="end">
          <div>
            <Typography.Text type="secondary" style={{ display: "block", marginBottom: 4, fontSize: 12 }}>
              {t("cluster.ttlLabel")}
            </Typography.Text>
            <InputNumber min={1} max={720} value={ttlHours} onChange={(v) => setTtlHours(v ?? 1)} />
          </div>
          <Button type="primary" loading={generating} onClick={onGenerate}>
            {generating ? t("common.loading") : t("cluster.generateToken")}
          </Button>
        </Space>
        {errorMsg && <Alert style={{ marginTop: 12 }} type="error" message={errorMsg} showIcon />}
      </Card>

      <Card size="small" title={t("cluster.tokenValue")}>
        {!token ? (
          <Typography.Text italic type="secondary">{t("cluster.noToken")}</Typography.Text>
        ) : (
          <>
            <pre
              style={{
                background: "#1f1f1f",
                color: "#73d13d",
                padding: 12,
                borderRadius: 6,
                fontSize: 11,
                wordBreak: "break-all",
                whiteSpace: "pre-wrap",
                userSelect: "all",
                marginBottom: 12,
              }}
            >
              {token}
            </pre>
            <Space>
              <Button icon={<CopyOutlined />} onClick={onCopy}>
                {copied ? t("cluster.tokenCopied") : t("cluster.copyToken")}
              </Button>
              <Typography.Text type="secondary" style={{ fontSize: 11 }}>
                TTL: {ttlHours}h
              </Typography.Text>
            </Space>
            <Typography.Paragraph
              type="secondary"
              style={{ fontSize: 11, marginTop: 12, marginBottom: 0, fontFamily: "ui-monospace, monospace", padding: 8, background: "#fafafa", borderRadius: 4 }}
            >
              {t("cluster.tokenHint")}
            </Typography.Paragraph>
          </>
        )}
      </Card>
    </Space>
  );
};
