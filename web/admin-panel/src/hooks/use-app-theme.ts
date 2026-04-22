import { useMemo } from "react";
import { theme as antTheme, type ThemeConfig } from "antd";
import { useUiStore, type AccentColor } from "../stores/ui-store";

// Maps the limited accent palette exposed in UI prefs to AntD primary tokens.
const accentToken: Record<AccentColor, string> = {
  blue: "#1677ff",
  purple: "#722ed1",
  green: "#52c41a",
  red: "#f5222d",
  orange: "#fa8c16",
};

export const useAppTheme = (): ThemeConfig => {
  const { themeMode, density, accent } = useUiStore();

  return useMemo<ThemeConfig>(() => {
    const algorithms = [
      themeMode === "dark" ? antTheme.darkAlgorithm : antTheme.defaultAlgorithm,
    ];
    if (density === "compact") {
      algorithms.push(antTheme.compactAlgorithm);
    }
    return {
      algorithm: algorithms,
      token: {
        colorPrimary: accentToken[accent],
        borderRadius: 6,
        fontFamily: "system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif",
      },
    };
  }, [themeMode, density, accent]);
};
