import { Badge, Tooltip } from "antd";
import { useGo } from "@refinedev/core";
import { useTranslation } from "react-i18next";

import { useEnforcementCapabilities } from "../hooks/use-enforcement-capabilities";
import { ModeTag } from "./mode-tag";

// S4 — global header pill. Shares the console's capabilities queryKey, so it adds
// no extra fetch. Reflects the live default mode + active override count and
// deep-links to the console. Read-only: no mode-flip from the header.
export const ModePill: React.FC = () => {
  const { t } = useTranslation();
  const go = useGo();
  const { result } = useEnforcementCapabilities();
  const active = result?.data?.active;

  // Hide when loading / errored / interop-disabled — the pill is informational.
  if (!active) return null;

  const overrideCount = Object.keys(active.overrides).length;
  const label = t(active.default_mode === "enforce" ? "enforcement.modeEnforce" : "enforcement.modeLogOnly");
  const aria = t("enforcement.pillAria", { mode: label });
  const open = () => go({ to: "/enforcement" });

  return (
    <Tooltip title={aria}>
      <span
        role="button"
        tabIndex={0}
        aria-label={aria}
        style={{ cursor: "pointer", display: "inline-flex" }}
        onClick={open}
        onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && open()}
      >
        <Badge count={overrideCount} size="small" offset={[2, -2]}>
          <ModeTag mode={active.default_mode} />
        </Badge>
      </span>
    </Tooltip>
  );
};
