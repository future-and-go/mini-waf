import { Card, Space, Row, Col, Input, Select, Button, Alert, Tag, Typography } from "antd";
import { ExperimentOutlined } from "@ant-design/icons";
import type { TFunction } from "i18next";
import { TIERS, verdictColor, type Tier, type TestResult } from "../types";

interface DecisionTesterProps {
  ip: string;
  host: string;
  tier: Tier;
  result: TestResult | null;
  isFetching: boolean;
  isError: boolean;
  onIpChange: (v: string) => void;
  onHostChange: (v: string) => void;
  onTierChange: (v: Tier) => void;
  onTest: () => void;
  t: TFunction;
}

export const DecisionTester: React.FC<DecisionTesterProps> = ({
  ip,
  host,
  tier,
  result,
  isFetching,
  isError,
  onIpChange,
  onHostChange,
  onTierChange,
  onTest,
  t,
}) => (
  <Card
    size="small"
    title={
      <Space>
        <ExperimentOutlined />
        <span>{t("accessLists.decisionTester")}</span>
      </Space>
    }
    style={{ position: "sticky", bottom: 16 }}
  >
    {isError && (
      <Alert
        type="warning"
        showIcon
        message={t("accessLists.testerUnavailable")}
        style={{ marginBottom: 12 }}
      />
    )}
    <Row gutter={[12, 12]} align="middle">
      <Col xs={24} sm={8}>
        <Input
          prefix={
            <Typography.Text type="secondary" style={{ fontSize: 11 }}>
              IP
            </Typography.Text>
          }
          value={ip}
          onChange={(e) => onIpChange(e.target.value)}
          placeholder="1.2.3.4"
          onPressEnter={onTest}
        />
      </Col>
      <Col xs={24} sm={7}>
        <Input
          prefix={
            <Typography.Text type="secondary" style={{ fontSize: 11 }}>
              Host
            </Typography.Text>
          }
          value={host}
          onChange={(e) => onHostChange(e.target.value)}
          placeholder="example.com"
          onPressEnter={onTest}
        />
      </Col>
      <Col xs={12} sm={5}>
        <Select
          style={{ width: "100%" }}
          value={tier}
          onChange={onTierChange}
          options={TIERS.map(({ key, label }) => ({ value: key, label }))}
        />
      </Col>
      <Col xs={12} sm={4}>
        <Button type="primary" style={{ width: "100%" }} loading={isFetching} onClick={onTest}>
          {t("common.test")}
        </Button>
      </Col>
    </Row>
    {result && (
      <div style={{ marginTop: 12 }}>
        <Space>
          <Tag
            color={verdictColor(result.verdict ?? "")}
            style={{ fontSize: 14, padding: "2px 12px" }}
          >
            {(result.verdict ?? "unknown").toUpperCase()}
          </Tag>
          {result.reason && (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {result.reason}
            </Typography.Text>
          )}
        </Space>
      </div>
    )}
  </Card>
);
