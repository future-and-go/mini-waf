import { Row, Col, Select, Button, Space } from "antd";
import { useTranslation } from "react-i18next";

const ACTION_OPTIONS = [
  { value: "", label: "" },
  { value: "block", label: "block" },
  { value: "log", label: "log" },
  { value: "allow", label: "allow" },
  { value: "challenge", label: "challenge" },
];

const HOURS_OPTIONS = [
  { value: 1, label: "1h" },
  { value: 6, label: "6h" },
  { value: 24, label: "24h" },
  { value: 48, label: "48h" },
  { value: 72, label: "72h" },
  { value: 168, label: "168h" },
  { value: 720, label: "720h" },
];

interface DashboardFiltersProps {
  hostCode: string;
  action: string;
  hours: number;
  hosts: Array<{ host_code: string; host: string }>;
  onChange: (filters: { hostCode: string; action: string; hours: number }) => void;
  loading?: boolean;
}

export const DashboardFilters: React.FC<DashboardFiltersProps> = ({
  hostCode,
  action,
  hours,
  hosts,
  onChange,
  loading,
}) => {
  const { t } = useTranslation();

  const hostOptions = hosts.map((h) => ({ value: h.host_code, label: h.host }));

  return (
    <Row gutter={[8, 8]} align="middle">
      <Col>
        <Space size={4} align="center">
          <span style={{ fontSize: 12, color: "#8c8c8c" }}>{t("dashboard.filterHost")}:</span>
          <Select
            style={{ width: 160 }}
            size="small"
            placeholder={t("dashboard.allHosts")}
            allowClear
            value={hostCode || undefined}
            options={hostOptions}
            loading={loading}
            onChange={(v) => onChange({ hostCode: v ?? "", action, hours })}
          />
        </Space>
      </Col>
      <Col>
        <Space size={4} align="center">
          <span style={{ fontSize: 12, color: "#8c8c8c" }}>{t("dashboard.filterAction")}:</span>
          <Select
            style={{ width: 120 }}
            size="small"
            value={action || ""}
            options={[
              { value: "", label: t("dashboard.allActions") },
              ...ACTION_OPTIONS.filter((o) => o.value !== ""),
            ]}
            onChange={(v) => onChange({ hostCode, action: v, hours })}
          />
        </Space>
      </Col>
      <Col>
        <Space size={4} align="center">
          <span style={{ fontSize: 12, color: "#8c8c8c" }}>{t("dashboard.filterWindow")}:</span>
          <Select
            style={{ width: 90 }}
            size="small"
            value={hours}
            options={HOURS_OPTIONS}
            onChange={(v) => onChange({ hostCode, action, hours: v })}
          />
        </Space>
      </Col>
      <Col>
        <Button
          size="small"
          onClick={() => onChange({ hostCode: "", action: "", hours: 24 })}
        >
          {t("dashboard.filterReset")}
        </Button>
      </Col>
    </Row>
  );
};
