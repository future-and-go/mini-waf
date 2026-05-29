import { Card, Table, Space, Input, Button, Popconfirm, Tag } from "antd";
import { ReloadOutlined, StopOutlined } from "@ant-design/icons";
import type { ColumnsType } from "antd/es/table";
import type { TFunction } from "i18next";
import type { BanEntry } from "../types";

interface BanTableProps {
  bans: BanEntry[];
  loading: boolean;
  fetching: boolean;
  ipFilter: string;
  isAdmin: boolean;
  rbacTooltip: string;
  onIpFilter: (v: string) => void;
  onRefetch: () => void;
  onUnban: (ip: string) => void;
  t: TFunction;
}

function formatDuration(secs: number): string {
  if (secs <= 0) return "expired";
  if (secs < 60) return `${secs}s`;
  const m = Math.floor(secs / 60);
  if (m < 60) return `${m}m ${secs % 60}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

const TtlCell: React.FC<{ ttlSecs: number }> = ({ ttlSecs }) => {
  if (ttlSecs <= 0) return <Tag color="default">expired</Tag>;
  if (ttlSecs < 60) return <Tag color="orange">{formatDuration(ttlSecs)}</Tag>;
  return <Tag color="red">{formatDuration(ttlSecs)}</Tag>;
};

const ExpiresAtCell: React.FC<{ ms: number }> = ({ ms }) => (
  <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>
    {new Date(ms).toLocaleString()}
  </span>
);

export const BanTable: React.FC<BanTableProps> = ({
  bans,
  loading,
  fetching,
  ipFilter,
  isAdmin,
  rbacTooltip,
  onIpFilter,
  onRefetch,
  onUnban,
  t,
}) => {
  const columns: ColumnsType<BanEntry> = [
    {
      title: t("ddos.ip"),
      dataIndex: "ip",
      width: 180,
      render: (v: string) => (
        <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>{v}</span>
      ),
    },
    {
      title: t("ddos.expiresAt"),
      dataIndex: "expires_at_ms",
      width: 200,
      render: (v: number) => <ExpiresAtCell ms={v} />,
    },
    {
      title: t("ddos.ttlRemaining"),
      dataIndex: "ttl_remaining_secs",
      width: 140,
      render: (v: number) => <TtlCell ttlSecs={v} />,
    },
    {
      title: "",
      key: "actions",
      width: 110,
      render: (_: unknown, r: BanEntry) => (
        <Popconfirm
          title={t("ddos.unbanConfirm", { ip: r.ip })}
          onConfirm={() => onUnban(r.ip)}
          disabled={!isAdmin}
        >
          <Button size="small" danger icon={<StopOutlined />} disabled={!isAdmin} title={rbacTooltip}>
            {t("ddos.unban")}
          </Button>
        </Popconfirm>
      ),
    },
  ];

  return (
    <Card
      size="small"
      title={
        <Space size={6}>
          <StopOutlined style={{ color: "#f5222d" }} />
          <span>{t("ddos.banTable")}</span>
        </Space>
      }
      extra={
        <Space size={8}>
          <Input
            size="small"
            placeholder={t("ddos.filterIp")}
            value={ipFilter}
            onChange={(e) => onIpFilter(e.target.value)}
            allowClear
            style={{ width: 160 }}
          />
          <Button size="small" icon={<ReloadOutlined spin={fetching} />} onClick={onRefetch} />
        </Space>
      }
    >
      <Table<BanEntry>
        rowKey="ip"
        size="small"
        dataSource={bans}
        columns={columns}
        loading={loading}
        pagination={{ pageSize: 20, showSizeChanger: false }}
        locale={{ emptyText: t("ddos.noBans") }}
        scroll={{ x: 640 }}
      />
    </Card>
  );
};
