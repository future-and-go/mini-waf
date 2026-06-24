import { Tag } from "antd";
import { SafetyOutlined, EyeOutlined } from "@ant-design/icons";
import { useTranslation } from "react-i18next";
import type { InteropMode } from "../types/api";

interface ModeTagProps {
  mode: InteropMode;
  // Hide the leading icon for dense table cells.
  showIcon?: boolean;
}

// Single source of truth for enforce/log_only visual styling, shared by the
// catalog, the runtime surfaces, the header pill, and the event correlation
// columns. enforce = success (green), log_only = warning (amber).
export const ModeTag: React.FC<ModeTagProps> = ({ mode, showIcon = true }) => {
  const { t } = useTranslation();
  const isEnforce = mode === "enforce";
  return (
    <Tag
      color={isEnforce ? "success" : "warning"}
      icon={showIcon ? (isEnforce ? <SafetyOutlined /> : <EyeOutlined />) : undefined}
      style={{ marginInlineEnd: 0 }}
    >
      {isEnforce ? t("enforcement.modeEnforce") : t("enforcement.modeLogOnly")}
    </Tag>
  );
};
