import { Row, Col, Typography, Space } from "antd";
import { useList, useCreate, useDelete } from "@refinedev/core";
import { useTranslation } from "react-i18next";
import { DualListRules } from "../../components/dual-list-rules";
import type { IpRule } from "../../types/api";

export const IpRulesPage: React.FC = () => {
  const { t } = useTranslation();

  const allow = useList<IpRule>({
    resource: "allow-ips",
    pagination: { mode: "off" },
    queryOptions: { staleTime: 30_000 },
  });
  const block = useList<IpRule>({
    resource: "block-ips",
    pagination: { mode: "off" },
    queryOptions: { staleTime: 30_000 },
  });

  const { mutate: createAllow } = useCreate();
  const { mutate: deleteAllow } = useDelete();
  const { mutate: createBlock } = useCreate();
  const { mutate: deleteBlock } = useDelete();

  const onAddAllow = (data: Record<string, unknown>) =>
    new Promise<void>((res, rej) =>
      createAllow(
        { resource: "allow-ips", values: data, successNotification: false },
        { onSuccess: () => { allow.query.refetch(); res(); }, onError: rej },
      ),
    );
  const onDelAllow = (id: string) =>
    new Promise<void>((res, rej) =>
      deleteAllow(
        { resource: "allow-ips", id, successNotification: false },
        { onSuccess: () => { allow.query.refetch(); res(); }, onError: rej },
      ),
    );
  const onAddBlock = (data: Record<string, unknown>) =>
    new Promise<void>((res, rej) =>
      createBlock(
        { resource: "block-ips", values: data, successNotification: false },
        { onSuccess: () => { block.query.refetch(); res(); }, onError: rej },
      ),
    );
  const onDelBlock = (id: string) =>
    new Promise<void>((res, rej) =>
      deleteBlock(
        { resource: "block-ips", id, successNotification: false },
        { onSuccess: () => { block.query.refetch(); res(); }, onError: rej },
      ),
    );

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Typography.Title level={4} style={{ margin: 0 }}>
        {t("ipRules.title")}
      </Typography.Title>
      <Row gutter={[12, 12]}>
        <Col xs={24} lg={12}>
          <DualListRules
            title={t("ipRules.allowList")}
            color="green"
            rows={Array.isArray(allow.result?.data) ? allow.result.data : []}
            fieldKey="ip_cidr"
            fieldLabel={t("ipRules.ipCidr")}
            onAdd={onAddAllow}
            onDelete={onDelAllow}
            loading={allow.query.isLoading}
          />
        </Col>
        <Col xs={24} lg={12}>
          <DualListRules
            title={t("ipRules.blockList")}
            color="red"
            rows={Array.isArray(block.result?.data) ? block.result.data : []}
            fieldKey="ip_cidr"
            fieldLabel={t("ipRules.ipCidr")}
            onAdd={onAddBlock}
            onDelete={onDelBlock}
            loading={block.query.isLoading}
          />
        </Col>
      </Row>
    </Space>
  );
};
