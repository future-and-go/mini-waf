import { Card, Space } from "antd";
import type React from "react";

interface SectionCardProps {
  icon: React.ReactNode;
  title: string;
  extra?: React.ReactNode;
  children: React.ReactNode;
}

export const SectionCard: React.FC<SectionCardProps> = ({ icon, title, extra, children }) => (
  <Card
    size="small"
    title={
      <Space size={6}>
        {icon}
        <span>{title}</span>
      </Space>
    }
    extra={extra}
  >
    {children}
  </Card>
);
