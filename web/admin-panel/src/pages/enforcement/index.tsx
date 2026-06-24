import { Typography } from "antd";
import { useTranslation } from "react-i18next";

const { Title, Paragraph } = Typography;

// Placeholder console shell — the capability catalog, runtime ops, plane map,
// and mode dial are wired in Phases 4–5.
export const EnforcementConsolePage: React.FC = () => {
  const { t } = useTranslation();
  return (
    <div style={{ maxWidth: 1200, margin: "0 auto" }}>
      <Title level={3}>{t("enforcement.title")}</Title>
      <Paragraph type="secondary">{t("enforcement.subtitle")}</Paragraph>
    </div>
  );
};
