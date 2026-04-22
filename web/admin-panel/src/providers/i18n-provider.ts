import type { I18nProvider } from "@refinedev/core";
import i18n from "../i18n/i18n";

// Refine ↔ react-i18next bridge.
// All UI strings live in src/i18n/locales/*.json; this provider only adapts
// the API surface Refine expects.
export const i18nProvider: I18nProvider = {
  translate: (key, options) => i18n.t(key, options) as string,
  changeLocale: (lang) => i18n.changeLanguage(lang),
  getLocale: () => i18n.language,
};
