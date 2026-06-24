import { useState } from "react";
import { Card, Button, Space, Typography, Tag, Alert, App } from "antd";
import { ReloadOutlined, ClearOutlined, SafetyCertificateOutlined } from "@ant-design/icons";
import { useCustomMutation } from "@refinedev/core";
import { useTranslation } from "react-i18next";

import type { ResetStateResponse, FlushCacheResponse } from "../../types/api";
import { ENFORCEMENT_ROUTES } from "../../providers/enforcement-provider";
import { fmtDateTime } from "../../utils/format";

const { Text } = Typography;

// S3 — Runtime operations. Reset also clears mode overrides server-side, so it
// triggers a console refetch. Flush handles the not-supported branch (Open Q #1):
// a missing `supported` field is treated as supported (current backend shape).
export const RuntimeOperations: React.FC<{ onRefetch: () => void }> = ({ onRefetch }) => {
  const { t } = useTranslation();
  const { modal, message } = App.useApp();
  const { mutate: resetMutate, mutation: resetM } = useCustomMutation<ResetStateResponse>();
  const { mutate: flushMutate, mutation: flushM } = useCustomMutation<FlushCacheResponse>();

  const [resetTs, setResetTs] = useState<number | null>(null);
  const [flushInfo, setFlushInfo] = useState<{ supported: boolean; ts?: number } | null>(null);

  const onReset = () =>
    modal.confirm({
      title: t("enforcement.resetConfirmTitle"),
      content: t("enforcement.resetConfirmBody"),
      okText: t("common.confirm"),
      cancelText: t("common.cancel"),
      okButtonProps: { danger: true },
      onOk: () =>
        new Promise<void>((resolve) => {
          resetMutate(
            { url: ENFORCEMENT_ROUTES.resetState, method: "post", values: {} },
            {
              onSuccess: (resp) => {
                setResetTs(resp.data?.ts_ms ?? null);
                message.success(t("enforcement.resetSuccess"));
                onRefetch();
              },
              onError: (err) => message.error(err.message),
              onSettled: () => resolve(),
            },
          );
        }),
    });

  const onFlush = () =>
    flushMutate(
      { url: ENFORCEMENT_ROUTES.flushCache, method: "post", values: {} },
      {
        onSuccess: (resp) => {
          const supported = resp.data?.supported !== false;
          setFlushInfo({ supported, ts: resp.data?.ts_ms });
          if (supported) message.success(t("enforcement.flushSuccess"));
        },
        onError: (err) => message.error(err.message),
      },
    );

  return (
    <Card title={t("enforcement.runtimeOpsTitle")}>
      <Space direction="vertical" size="middle" style={{ width: "100%" }}>
        <Space align="start" wrap>
          <Button danger icon={<ReloadOutlined />} loading={resetM.isPending} onClick={onReset}>
            {t("enforcement.resetState")}
          </Button>
          <Text type="secondary" style={{ maxWidth: 420 }}>{t("enforcement.resetStateDesc")}</Text>
        </Space>
        {resetTs !== null && (
          <Text type="secondary">
            <Tag color="success" icon={<SafetyCertificateOutlined />}>{t("enforcement.auditPreserved")}</Tag>
            {t("enforcement.appliedAt", { time: fmtDateTime(resetTs) })}
          </Text>
        )}

        <Space align="start" wrap>
          <Button icon={<ClearOutlined />} loading={flushM.isPending} onClick={onFlush}>
            {t("enforcement.flushCache")}
          </Button>
          <Text type="secondary" style={{ maxWidth: 420 }}>{t("enforcement.flushCacheDesc")}</Text>
        </Space>
        {flushInfo && !flushInfo.supported && (
          <Alert type="info" showIcon message={t("enforcement.flushNotSupported")} />
        )}
        {flushInfo?.supported && flushInfo.ts !== undefined && (
          <Text type="secondary">{t("enforcement.appliedAt", { time: fmtDateTime(flushInfo.ts) })}</Text>
        )}
      </Space>
    </Card>
  );
};
