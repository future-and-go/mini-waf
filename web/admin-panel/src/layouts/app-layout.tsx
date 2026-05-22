import { useMemo } from "react";
import { Layout, Menu, Typography, Button, Select, Space, Dropdown, Avatar, theme, Badge } from "antd";
import type { MenuProps } from "antd";
import {
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  LogoutOutlined,
  BgColorsOutlined,
  GlobalOutlined,
  UserOutlined,
} from "@ant-design/icons";
import { useTranslation } from "react-i18next";
import { useGetIdentity, useLogout, useGo, useCustom } from "@refinedev/core";
import { useLocation } from "react-router-dom";
import { navItems, type NavItem } from "../utils/nav-items";
import { useUiStore } from "../stores/ui-store";

const { Sider, Header, Content } = Layout;

interface MenuGroup {
  section: string | null;
  items: NavItem[];
}

const groupBySection = (items: NavItem[]): MenuGroup[] => {
  const groups: MenuGroup[] = [];
  let current: MenuGroup | null = null;
  for (const item of items) {
    const section = item.section ?? null;
    if (!current || current.section !== section) {
      current = { section, items: [] };
      groups.push(current);
    }
    current.items.push(item);
  }
  return groups;
};

interface IdentityShape {
  name?: string;
  role?: string;
}

interface AppLayoutProps {
  children: React.ReactNode;
}

export const AppLayout: React.FC<AppLayoutProps> = ({ children }) => {
  const { t, i18n } = useTranslation();
  const { collapsed, toggleCollapsed, themeMode, setThemeMode } = useUiStore();
  const go = useGo();
  const location = useLocation();
  const { mutate: logout } = useLogout();
  const { data: identity } = useGetIdentity<IdentityShape>();
  const { token } = theme.useToken();

  // XFF spoof badge on bot-management nav item (Task 2c)
  const xffQuery = useCustom<{ data: unknown[]; total: number }>({
    url: "/api/security-events",
    method: "get",
    config: { query: { rule_id: "BOT-XFF-SPOOF", page_size: 1 } },
    queryOptions: { staleTime: 60_000, refetchInterval: 60_000, retry: false },
  });
  const xffCount = xffQuery.result?.data?.total ?? 0;

  // Honeypot dot badge on security-events nav item (Task 5d)
  const honeypotQuery = useCustom<{ data: Array<{ created_at: string }>; total: number }>({
    url: "/api/security-events",
    method: "get",
    config: { query: { rule_id: "HONEY", page_size: 1 } },
    queryOptions: { staleTime: 30_000, refetchInterval: 30_000, retry: false },
  });
  const honeypotLatest = honeypotQuery.result?.data?.data?.[0]?.created_at;
  const honeypotDot = honeypotLatest
    ? Date.now() - new Date(honeypotLatest).getTime() < 5 * 60_000
    : false;

  const groups = useMemo(() => groupBySection(navItems), []);

  // Active key: longest matching prefix wins so /cluster/nodes/X highlights /cluster.
  const activeKey = useMemo(() => {
    const matches = navItems
      .filter((item) => location.pathname === item.path || location.pathname.startsWith(item.path + "/"))
      .sort((a, b) => b.path.length - a.path.length);
    return matches[0]?.key ?? "dashboard";
  }, [location.pathname]);

  const getNavLabel = (itemKey: string, base: string): React.ReactNode => {
    if (itemKey === "bot-management" && xffCount > 0) {
      return (
        <span style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          {base}
          <Badge count={xffCount} size="small" style={{ marginLeft: 6 }} />
        </span>
      );
    }
    if (itemKey === "security-events" && honeypotDot) {
      return (
        <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
          {base}
          <Badge dot status="error" />
        </span>
      );
    }
    return base;
  };

  // AntD Menu items can be: leaf, divider, or group. flatMap mixes shapes;
  // annotate as MenuItem[] so TS doesn't infer a narrow leaf-only union.
  type MenuItem = NonNullable<MenuProps["items"]>[number];
  const menuItems: MenuItem[] = groups.flatMap((g): MenuItem[] => {
    const children: MenuItem[] = g.items.map((item) => {
      const Icon = item.icon;
      return {
        key: item.key,
        icon: <Icon />,
        label: getNavLabel(item.key, t(item.i18nKey)),
        onClick: () => go({ to: item.path, type: "push" }),
      };
    });
    if (g.section) {
      return [
        { type: "divider", key: `div-${g.section}` },
        {
          type: "group",
          key: `grp-${g.section}`,
          label: t(g.section),
          children,
        },
      ];
    }
    return children;
  });

  return (
    <Layout style={{ minHeight: "100vh" }}>
      <Sider
        theme={themeMode === "dark" ? "dark" : "light"}
        collapsible
        collapsed={collapsed}
        onCollapse={toggleCollapsed}
        trigger={null}
        width={240}
        style={{ borderRight: `1px solid ${token.colorBorderSecondary}` }}
      >
        <div
          style={{
            height: 64,
            display: "flex",
            alignItems: "center",
            justifyContent: collapsed ? "center" : "flex-start",
            padding: collapsed ? 0 : "0 20px",
            borderBottom: `1px solid ${token.colorBorderSecondary}`,
          }}
        >
          {collapsed ? (
            <Typography.Title level={5} style={{ margin: 0 }}>
              W
            </Typography.Title>
          ) : (
            <div>
              <Typography.Title level={5} style={{ margin: 0 }}>
                F&G WAF
              </Typography.Title>
              <Typography.Text type="secondary" style={{ fontSize: 11 }}>
                {t("auth.adminPanel")}
              </Typography.Text>
            </div>
          )}
        </div>
        <Menu
          theme={themeMode === "dark" ? "dark" : "light"}
          mode="inline"
          selectedKeys={[activeKey]}
          items={menuItems}
          style={{ borderInlineEnd: "none" }}
        />
      </Sider>

      <Layout>
        <Header
          style={{
            padding: "0 16px",
            background: token.colorBgContainer,
            borderBottom: `1px solid ${token.colorBorderSecondary}`,
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            height: 56,
          }}
        >
          <Button
            type="text"
            icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
            onClick={toggleCollapsed}
          />

          <Space size="middle">
            <Select
              size="small"
              value={i18n.language?.split("-")[0] ?? "en"}
              onChange={(lng) => i18n.changeLanguage(lng)}
              options={[
                { value: "en", label: "English" },
                { value: "vi", label: "Tiếng Việt" },
                { value: "zh", label: "中文" },
              ]}
              suffixIcon={<GlobalOutlined />}
              style={{ width: 130 }}
            />

            <Button
              size="small"
              icon={<BgColorsOutlined />}
              onClick={() => setThemeMode(themeMode === "dark" ? "light" : "dark")}
            >
              {themeMode === "dark" ? t("common.themeLight") : t("common.themeDark")}
            </Button>

            <Dropdown
              menu={{
                items: [
                  {
                    key: "logout",
                    icon: <LogoutOutlined />,
                    label: t("common.logout"),
                    onClick: () => logout(),
                  },
                ],
              }}
              placement="bottomRight"
            >
              <Space style={{ cursor: "pointer" }}>
                <Avatar size="small" icon={<UserOutlined />} />
                <span>{identity?.name ?? "user"}</span>
              </Space>
            </Dropdown>
          </Space>
        </Header>

        <Content style={{ padding: 16, background: token.colorBgLayout }}>
          {children}
        </Content>
      </Layout>
    </Layout>
  );
};
