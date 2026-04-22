import { Row, Col, Typography, Space } from "antd";
import { useList, useCreate, useDelete } from "@refinedev/core";
import { useTranslation } from "react-i18next";
import { DualListRules } from "../../components/dual-list-rules";
import type { UrlRule } from "../../types/api";

export const UrlRulesPage: React.FC = () => {
  const { t } = useTranslation();

  const allow = useList<UrlRule>({
    resource: "allow-urls",
    pagination: { mode: "off" },
    queryOptions: { staleTime: 30_000 },
  });
  const block = useList<UrlRule>({
    resource: "block-urls",
    pagination: { mode: "off" },
    queryOptions: { staleTime: 30_000 },
  });

  const { mutate: createAllow } = useCreate();
  const { mutate: deleteAllow } = useDelete();
  const { mutate: createBlock } = useCreate();
  const { mutate: deleteBlock } = useDelete();

  // Backend defaults match_type to prefix when omitted; preserve legacy default.
  const wrap = (data: Record<string, unknown>) => ({ ...data, match_type: "prefix" });

  const onAddAllow = (data: Record<string, unknown>) =>
    new Promise<void>((res, rej) =>
      createAllow(
        { resource: "allow-urls", values: wrap(data), successNotification: false },
        { onSuccess: () => { allow.query.refetch(); res(); }, onError: rej },
      ),
    );
  const onDelAllow = (id: string) =>
    new Promise<void>((res, rej) =>
      deleteAllow(
        { resource: "allow-urls", id, successNotification: false },
        { onSuccess: () => { allow.query.refetch(); res(); }, onError: rej },
      ),
    );
  const onAddBlock = (data: Record<string, unknown>) =>
    new Promise<void>((res, rej) =>
      createBlock(
        { resource: "block-urls", values: wrap(data), successNotification: false },
        { onSuccess: () => { block.query.refetch(); res(); }, onError: rej },
      ),
    );
  const onDelBlock = (id: string) =>
    new Promise<void>((res, rej) =>
      deleteBlock(
        { resource: "block-urls", id, successNotification: false },
        { onSuccess: () => { block.query.refetch(); res(); }, onError: rej },
      ),
    );

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Typography.Title level={4} style={{ margin: 0 }}>
        {t("urlRules.title")}
      </Typography.Title>
      <Row gutter={[12, 12]}>
        <Col xs={24} lg={12}>
          <DualListRules
            title={t("urlRules.allowUrls")}
            color="green"
            rows={Array.isArray(allow.result?.data) ? allow.result.data : []}
            fieldKey="url_pattern"
            fieldLabel={t("urlRules.urlPattern")}
            onAdd={onAddAllow}
            onDelete={onDelAllow}
            loading={allow.query.isLoading}
          />
        </Col>
        <Col xs={24} lg={12}>
          <DualListRules
            title={t("urlRules.blockUrls")}
            color="red"
            rows={Array.isArray(block.result?.data) ? block.result.data : []}
            fieldKey="url_pattern"
            fieldLabel={t("urlRules.urlPattern")}
            onAdd={onAddBlock}
            onDelete={onDelBlock}
            loading={block.query.isLoading}
          />
        </Col>
      </Row>
    </Space>
  );
};
