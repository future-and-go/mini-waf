import { create } from "zustand";
import { persist } from "zustand/middleware";

// Single client-side store for ephemeral UI prefs.
// Server state lives in TanStack Query (Refine); do not duplicate here.

export type ThemeMode = "light" | "dark";
export type ThemeDensity = "comfortable" | "compact";
export type AccentColor = "blue" | "purple" | "green" | "red" | "orange";

interface UiState {
  themeMode: ThemeMode;
  density: ThemeDensity;
  accent: AccentColor;
  collapsed: boolean;
  selectedHostCode: string;
  setThemeMode: (m: ThemeMode) => void;
  setDensity: (d: ThemeDensity) => void;
  setAccent: (a: AccentColor) => void;
  toggleCollapsed: () => void;
  setSelectedHostCode: (h: string) => void;
}

export const useUiStore = create<UiState>()(
  persist(
    (set) => ({
      themeMode: "light",
      density: "comfortable",
      accent: "blue",
      collapsed: false,
      selectedHostCode: "",
      setThemeMode: (themeMode) => set({ themeMode }),
      setDensity: (density) => set({ density }),
      setAccent: (accent) => set({ accent }),
      toggleCollapsed: () => set((s) => ({ collapsed: !s.collapsed })),
      setSelectedHostCode: (selectedHostCode) => set({ selectedHostCode }),
    }),
    { name: "prx-waf-ui" },
  ),
);
