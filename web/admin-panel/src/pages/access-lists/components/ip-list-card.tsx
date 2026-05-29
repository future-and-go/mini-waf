import { Card, Space, Badge, Input, Typography, Alert } from "antd";
import { SafetyOutlined, StopOutlined } from "@ant-design/icons";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { joinLines, parseLines } from "../types";

interface IpListCardProps {
  title: string;
  value: string[];
  onChange: (next: string[]) => void;
  disabled?: boolean;
  color?: "green" | "red";
}

export const IpListCard: React.FC<IpListCardProps> = ({
  title,
  value,
  onChange,
  disabled,
  color = "green",
}) => {
  const [raw, setRaw] = useState(joinLines(value));
  const { t } = useTranslation();

  useEffect(() => {
    setRaw(joinLines(value));
  }, [value]);

  const onBlur = () => {
    onChange(parseLines(raw));
  };

  const count = parseLines(raw).length;
  const warn = count > 50_000;
  const accent = color === "green" ? "#52c41a" : "#f5222d";

  return (
    <Card
      size="small"
      title={
        <Space>
          {color === "green" ? (
            <SafetyOutlined style={{ color: accent }} />
          ) : (
            <StopOutlined style={{ color: accent }} />
          )}
          <span>{title}</span>
          <Badge count={count} overflowCount={999_999} style={{ backgroundColor: accent }} />
        </Space>
      }
    >
      {warn && (
        <Alert
          type="warning"
          showIcon
          message={t("accessLists.largeListWarning")}
          style={{ marginBottom: 8 }}
        />
      )}
      <Input.TextArea
        value={raw}
        onChange={(e) => setRaw(e.target.value)}
        onBlur={onBlur}
        disabled={disabled}
        rows={8}
        placeholder="1.2.3.4&#10;10.0.0.0/8"
        style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}
      />
      <Typography.Text type="secondary" style={{ fontSize: 11 }}>
        {t("accessLists.parseHint")}
      </Typography.Text>
    </Card>
  );
};
