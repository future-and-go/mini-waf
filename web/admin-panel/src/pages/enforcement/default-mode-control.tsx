import { Segmented, Button, Space, Typography, Dropdown, App } from "antd";
import { ReloadOutlined, DownOutlined, SafetyOutlined, EyeOutlined } from "@ant-design/icons";
import { useCustomMutation } from "@refinedev/core";
import { useTranslation } from "react-i18next";

import type { InteropMode, SetProfileResponse } from "../../types/api";
import { ENFORCEMENT_ROUTES } from "../../providers/enforcement-provider";
import { fmtTime } from "../../utils/format";

const { Text } = Typography;

interface Props {
  defaultMode: InteropMode;
  dataUpdatedAt: number;
  isFetching: boolean;
  onRefetch: () => void;
}

// Header strip: default-mode dial (Segmented) + apply-all shortcut + refresh +
// last-sync. Changing the dial is a global change (clears all overrides), so it
// is confirmed first. A bare Segmented change is treated as the same intent.
export const DefaultModeControl: React.FC<Props> = ({ defaultMode, dataUpdatedAt, isFetching, onRefetch }) => {
  const { t } = useTranslation();
  const { modal, message } = App.useApp();
  const { mutate, mutation } = useCustomMutation<SetProfileResponse>();
  const pending = mutation.isPending;

  const label = (m: InteropMode) => t(m === "enforce" ? "enforcement.modeEnforce" : "enforcement.modeLogOnly");

  const applyAll = (mode: InteropMode) => {
    mutate(
      { url: ENFORCEMENT_ROUTES.setProfile, method: "post", values: { scope: "all", mode } },
      {
        onSuccess: () => {
          message.success(t("enforcement.applied"));
          onRefetch();
        },
        onError: (err) => message.error(err.message),
      },
    );
  };

  const confirmApplyAll = (mode: InteropMode) => {
    modal.confirm({
      title: t("enforcement.confirmDefaultTitle"),
      content: t("enforcement.confirmDefaultBody", { mode: label(mode) }),
      okText: t("common.confirm"),
      cancelText: t("common.cancel"),
      onOk: () => applyAll(mode),
    });
  };

  return (
    <Space wrap align="center" size="middle">
      <Space direction="vertical" size={0}>
        <Text strong>{t("enforcement.defaultMode")}</Text>
        <Text type="secondary" style={{ fontSize: 12 }}>{t("enforcement.defaultModeHint")}</Text>
      </Space>

      <Segmented<InteropMode>
        value={defaultMode}
        disabled={pending}
        onChange={(mode) => mode !== defaultMode && confirmApplyAll(mode)}
        options={[
          { value: "enforce", label: label("enforce"), icon: <SafetyOutlined /> },
          { value: "log_only", label: label("log_only"), icon: <EyeOutlined /> },
        ]}
      />

      <Dropdown
        disabled={pending}
        menu={{
          items: [
            { key: "enforce", label: label("enforce"), icon: <SafetyOutlined /> },
            { key: "log_only", label: label("log_only"), icon: <EyeOutlined /> },
          ],
          onClick: ({ key }) => confirmApplyAll(key as InteropMode),
        }}
      >
        <Button>
          <Space>
            {t("enforcement.applyAll")}
            <DownOutlined />
          </Space>
        </Button>
      </Dropdown>

      <Button icon={<ReloadOutlined />} loading={isFetching} onClick={onRefetch}>
        {t("common.refresh")}
      </Button>

      {dataUpdatedAt > 0 && (
        <Text type="secondary" style={{ fontSize: 12 }}>
          {t("enforcement.lastSync", { time: fmtTime(dataUpdatedAt) })}
        </Text>
      )}
    </Space>
  );
};
