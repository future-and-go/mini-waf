# Admin UI Design Guidelines

## Technology Stack

- **React** (18.3.1) — Hooks + functional components
- **TypeScript** (5.7) — Full type safety
- **Vite** (8.0.9) — Dev server (hot reload) + production bundler
- **Refine** (5.0.12) — Admin framework (hooks, data providers, routing)
- **Ant Design** (5.22.5) — Enterprise UI component library
- **React Query** (5.62.7) — Server state management
- **React Router** (7.0.0) — Client-side routing (history mode)
- **Zustand** (5.0.2) — Lightweight client state (auth, UI state)
- **Axios** (1.7.9) — HTTP client with interceptors
- **i18next** (24.0.5) — Internationalization (11 locales)
- **Ant Design Icons** (5.5.2) — Icon library
- **Refine + Ant Design integration** — Seamless layouts, form builders, table paging

## Project Structure

```
web/admin-panel/
├── src/
│   ├── main.tsx              # React root + Vite entry
│   ├── App.tsx               # Root layout wrapper
│   │
│   ├── pages/                # Route-level pages
│   │   ├── dashboard/        # Dashboard with charts
│   │   ├── login/            # JWT + TOTP login
│   │   ├── hosts/            # Vhost CRUD
│   │   ├── rules/            # Rule management (enable/disable)
│   │   ├── ip-rules/         # IP allow/block lists
│   │   ├── url-rules/        # URL pattern lists
│   │   ├── security-events/  # Attack log viewer
│   │   ├── certificates/     # TLS cert management
│   │   ├── cluster/          # Cluster topology + health
│   │   ├── settings/         # Panel config (risk thresholds, etc.)
│   │   └── ...               # More pages per feature area
│   │
│   ├── components/           # Reusable components
│   │   ├── Layout.tsx        # Refine Layout provider wrapper
│   │   ├── Sider.tsx         # Sidebar nav with Refine integration
│   │   ├── Header.tsx        # Top bar (user menu, breadcrumbs)
│   │   ├── StatCard.tsx      # Metric card (RPS, blocked %, etc.)
│   │   ├── RuleTable.tsx     # Refine Table + pagination for rules
│   │   └── ...               # More reusable components
│   │
│   ├── hooks/                # Custom React hooks
│   │   ├── useAuth.ts        # Auth state (Zustand store)
│   │   ├── useNotification.ts # Message/notification helpers
│   │   └── ...
│   │
│   ├── stores/               # Zustand state management
│   │   ├── auth.ts           # User, JWT token, TOTP secret
│   │   ├── ui.ts             # Collapsed sidebar, theme, etc.
│   │   └── ...
│   │
│   ├── api/                  # API client + data providers
│   │   ├── client.ts         # Axios instance + interceptors
│   │   ├── auth.ts           # Login, logout, refresh, verify TOTP
│   │   ├── hosts.ts          # Host CRUD + queries
│   │   ├── rules.ts          # Rule enable/disable
│   │   ├── ip-rules.ts       # IP list CRUD
│   │   ├── url-rules.ts      # URL list CRUD
│   │   ├── certificates.ts   # TLS cert management
│   │   ├── events.ts         # Security event queries
│   │   ├── stats.ts          # Metrics + time-series
│   │   ├── cluster.ts        # Cluster API
│   │   ├── panel-config.ts   # Panel config GET/PUT
│   │   └── ...
│   │
│   ├── i18n/                 # Internationalization
│   │   ├── config.ts         # i18next setup
│   │   └── locales/
│   │       ├── en.ts         # English (base)
│   │       ├── zh.ts         # Simplified Chinese
│   │       ├── ru.ts         # Russian
│   │       ├── ka.ts         # Georgian
│   │       ├── ar.ts         # Arabic
│   │       ├── de.ts         # German
│   │       ├── es.ts         # Spanish
│   │       ├── fr.ts         # French
│   │       ├── ja.ts         # Japanese
│   │       ├── ko.ts         # Korean
│   │       └── et.ts         # Estonian
│   │
│   ├── types/                # TypeScript interfaces
│   │   ├── api.ts            # API response types
│   │   ├── domain.ts         # Business domain types
│   │   └── index.ts
│   │
│   └── styles/
│       └── globals.css       # Global Ant Design + custom CSS
│
├── index.html                # HTML entry point
├── package.json
├── vite.config.ts
├── tsconfig.json
└── README.md
```

## Component Patterns

### 1. Layout with Refine

**File: `components/Layout.tsx`**

Uses Refine's `<Authenticated>`, `<Layout>`, and `<Sider>` to wrap page content. Ant Design theme config provided via `ConfigProvider`.

```tsx
import { Authenticated, Refine } from "@refinedev/core";
import { AntdApp, ConfigProvider, Layout, theme } from "antd";
import { useTheme } from "./hooks/useTheme";

export const LayoutComponent: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const { isDark } = useTheme();
  const { defaultAlgorithm, darkAlgorithm } = theme;

  return (
    <ConfigProvider theme={{ algorithm: isDark ? darkAlgorithm : defaultAlgorithm }}>
      <AntdApp>
        <Layout style={{ minHeight: "100vh" }}>
          <Layout.Sider collapsible trigger={null} collapsed={false}>
            {/* Navigation menu */}
          </Layout.Sider>
          <Layout>
            <Layout.Header>
              {/* Top bar with breadcrumbs + user menu */}
            </Layout.Header>
            <Layout.Content style={{ padding: "24px" }}>
              {children}
            </Layout.Content>
          </Layout>
        </Layout>
      </AntdApp>
    </ConfigProvider>
  );
};
```

### 2. StatCard Component

**File: `components/StatCard.tsx`**

```tsx
import { Card, Space, Statistic } from "antd";
import { ArrowUpOutlined, ArrowDownOutlined } from "@ant-design/icons";

interface Props {
  label: string;
  value: string | number;
  change?: string;
  trend?: "up" | "down";
  icon?: React.ReactNode;
}

export const StatCard: React.FC<Props> = ({
  label,
  value,
  change,
  trend = "up",
  icon,
}) => {
  return (
    <Card hoverable>
      <Space direction="vertical" style={{ width: "100%" }}>
        <span style={{ fontSize: "12px", color: "#999" }}>{label}</span>
        <Statistic
          value={value}
          prefix={icon}
          suffix={
            change ? (
              trend === "up" ? (
                <ArrowUpOutlined style={{ color: "#52c41a" }} />
              ) : (
                <ArrowDownOutlined style={{ color: "#ff4d4f" }} />
              )
            ) : null
          }
        />
        {change && (
          <span style={{ color: trend === "up" ? "#52c41a" : "#ff4d4f", fontSize: "12px" }}>
            {change}
          </span>
        )}
      </Space>
    </Card>
  );
};
```

### 3. RuleTable Component (Using Refine + Ant Design Table)

**File: `components/RuleTable.tsx`**

Uses Refine's `useTable()` hook + Ant Design Table for automatic pagination, sorting, filtering.

```tsx
import { useTable } from "@refinedev/antd";
import { Button, Input, Select, Space, Table, Tag } from "antd";
import { useState } from "react";

interface Rule {
  id: string;
  name: string;
  category: string;
  enabled: boolean;
}

interface Props {
  onToggle: (rule: Rule) => Promise<void>;
  onEdit: (rule: Rule) => void;
  onDelete: (rule: Rule) => Promise<void>;
}

export const RuleTable: React.FC<Props> = ({ onToggle, onEdit, onDelete }) => {
  const { tableProps, searchFormProps } = useTable<Rule>({
    resource: "rules",
    pagination: { pageSize: 20 },
    queryOptions: { queryKey: ["rules"] },
  });

  const [category, setCategory] = useState<string>("");

  const columns = [
    { dataIndex: "id", title: "Rule ID", width: 120 },
    { dataIndex: "name", title: "Name", ellipsis: true },
    {
      dataIndex: "category",
      title: "Category",
      render: (text: string) => {
        const colors: Record<string, string> = {
          xss: "red",
          sqli: "orange",
          rce: "red",
          scanner: "gold",
        };
        return <Tag color={colors[text] || "default"}>{text}</Tag>;
      },
    },
    {
      dataIndex: "enabled",
      title: "Enabled",
      render: (enabled: boolean) => (
        <span style={{ color: enabled ? "#52c41a" : "#ff4d4f" }}>
          {enabled ? "Yes" : "No"}
        </span>
      ),
    },
    {
      title: "Actions",
      render: (_: any, rule: Rule) => (
        <Space size="small">
          <Button type="link" onClick={() => onEdit(rule)}>
            Edit
          </Button>
          <Button type="link" danger onClick={() => onDelete(rule)}>
            Delete
          </Button>
        </Space>
      ),
    },
  ];

  return (
    <div>
      <Space style={{ marginBottom: "16px" }}>
        <Input.Search
          placeholder="Search rules..."
          style={{ width: 200 }}
          {...searchFormProps}
        />
        <Select
          value={category}
          onChange={setCategory}
          style={{ width: 150 }}
          placeholder="Filter by category"
          options={[
            { value: "", label: "All Categories" },
            { value: "xss", label: "XSS" },
            { value: "sqli", label: "SQL Injection" },
          ]}
        />
      </Space>
      <Table<Rule> columns={columns} {...tableProps} rowKey="id" />
    </div>
  );
};
```

### 4. Custom Hook for Data Fetching

**File: `hooks/useHosts.ts`**

Uses React Query (TanStack Query) for server state management.

```tsx
import { useQuery, useMutation } from "@tanstack/react-query";
import { hostApi } from "../api/hosts";

export const useHosts = () => {
  const query = useQuery({
    queryKey: ["hosts"],
    queryFn: hostApi.list,
  });

  const createMutation = useMutation({
    mutationFn: hostApi.create,
    onSuccess: () => {
      query.refetch();
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }) => hostApi.update(id, data),
    onSuccess: () => {
      query.refetch();
    },
  });

  return {
    hosts: query.data || [],
    isLoading: query.isLoading,
    createHost: createMutation.mutate,
    updateHost: updateMutation.mutate,
  };
};
```

### 5. Auth Hook with Zustand

**File: `hooks/useAuth.ts`**

```tsx
import { create } from "zustand";
import { authApi } from "../api/auth";

interface AuthStore {
  user: { username: string } | null;
  token: string | null;
  login: (username: string, password: string, totp?: string) => Promise<void>;
  logout: () => void;
  verifyTotp: (secret: string, code: string) => Promise<boolean>;
}

export const useAuthStore = create<AuthStore>((set) => ({
  user: null,
  token: null,
  login: async (username, password, totp) => {
    const { token, user } = await authApi.login(username, password, totp);
    localStorage.setItem("token", token);
    set({ token, user });
  },
  logout: () => {
    localStorage.removeItem("token");
    set({ token: null, user: null });
  },
  verifyTotp: async (secret, code) => {
    return await authApi.verifyTotp(secret, code);
  },
}));

export const useAuth = () => useAuthStore();
```

## Page Example: Dashboard

**File: `pages/dashboard/index.tsx`**

```tsx
import { Row, Col, Card, Space, Tag } from "antd";
import { useQuery } from "@tanstack/react-query";
import { statsApi } from "../../api/stats";
import { StatCard } from "../../components/StatCard";
import { RuleTable } from "../../components/RuleTable";

export const DashboardPage: React.FC = () => {
  const statsQuery = useQuery({
    queryKey: ["stats"],
    queryFn: statsApi.getSummary,
    refetchInterval: 5000, // Refresh every 5s
  });

  const eventsQuery = useQuery({
    queryKey: ["recent-events"],
    queryFn: () => statsApi.getRecentEvents(10),
    refetchInterval: 3000,
  });

  const stats = statsQuery.data;
  const recentEvents = eventsQuery.data || [];

  return (
    <Space direction="vertical" style={{ width: "100%" }}>
      {/* Stats Row */}
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} lg={6}>
          <StatCard
            label="Requests/sec"
            value={stats?.rps || 0}
            change={`+${stats?.rpsChange || 0}% vs last hour`}
            trend="up"
          />
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <StatCard
            label="Blocked"
            value={stats?.blockedCount || 0}
            change={`${stats?.blockedPercent || 0}% blocked`}
          />
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <StatCard label="Active Rules" value={stats?.activeRules || 0} />
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <StatCard label="Cluster Nodes" value={stats?.clusterNodes || 0} />
        </Col>
      </Row>

      {/* Charts Row */}
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={12}>
          <Card title="Traffic Over Time">
            {/* Chart component via @ant-design/plots */}
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card title="Top Rules">
            <RuleTable />
          </Card>
        </Col>
      </Row>

      {/* Recent Events */}
      <Card title="Recent Attacks">
        {recentEvents.map((event) => (
          <div key={event.id} style={{ padding: "8px 0" }}>
            <Space>
              <span>{event.rule}</span>
              <span>({event.ip})</span>
              <Tag color={event.severity === "critical" ? "red" : "orange"}>
                {event.severity}
              </Tag>
            </Space>
          </div>
        ))}
      </Card>
    </Space>
  );
};
```

## i18n Setup (using i18next)

Translation keys use dot notation:

**File: `i18n/locales/en.ts`**

```typescript
export const en = {
  common: {
    save: "Save",
    cancel: "Cancel",
    delete: "Delete",
    edit: "Edit",
    loading: "Loading...",
  },
  nav: {
    dashboard: "Dashboard",
    hosts: "Hosts",
    rules: "Rules",
    cluster: "Cluster",
    settings: "Settings",
  },
  pages: {
    dashboard: {
      title: "Dashboard",
      stats: {
        rps: "Requests per Second",
        blocked: "Blocked Requests",
      },
    },
  },
  errors: {
    notFound: "Page not found",
    unauthorized: "Unauthorized",
    serverError: "Server error",
  },
};
```

**File: `i18n/config.ts`**

```tsx
import i18n from "i18next";
import LanguageDetector from "i18next-browser-languagedetector";
import { initReactI18next } from "react-i18next";
import { en } from "./locales/en";
import { zh } from "./locales/zh";

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: { en: { translation: en }, zh: { translation: zh } },
    fallbackLng: "en",
    interpolation: { escapeValue: false },
  });

export default i18n;
```

**Usage in components:**

```tsx
import { useTranslation } from "react-i18next";

export const LoginPage: React.FC = () => {
  const { t } = useTranslation();
  return <h1>{t("pages.dashboard.title")}</h1>;
};
```

## API Client Patterns

### Axios Instance with Interceptors

**File: `api/client.ts`**

```typescript
import axios, { AxiosInstance, AxiosError } from "axios";
import { useAuthStore } from "../hooks/useAuth";

const api: AxiosInstance = axios.create({
  baseURL: "/api",
  timeout: 15000,
});

// Request interceptor: add JWT
api.interceptors.request.use((config) => {
  const authStore = useAuthStore.getState();
  if (authStore.token) {
    config.headers.Authorization = `Bearer ${authStore.token}`;
  }
  return config;
});

// Response interceptor: auto-logout on 401
api.interceptors.response.use(
  (response) => response,
  (error: AxiosError) => {
    if (error.response?.status === 401) {
      useAuthStore.getState().logout();
      window.location.href = "/login";
    }
    return Promise.reject(error);
  }
);

export default api;
```

### API Module Pattern

**File: `api/hosts.ts`**

```typescript
import api from "./client";

export interface Host {
  id: string;
  name: string;
  upstream_url: string;
  enabled: boolean;
}

export const hostApi = {
  list: async (): Promise<Host[]> => {
    const res = await api.get("/hosts");
    return res.data.data; // Adjust based on actual response structure
  },

  get: async (id: string): Promise<Host> => {
    const res = await api.get(`/hosts/${id}`);
    return res.data.data;
  },

  create: async (host: Omit<Host, "id">): Promise<Host> => {
    const res = await api.post("/hosts", host);
    return res.data.data;
  },

  update: async (id: string, host: Partial<Host>): Promise<Host> => {
    const res = await api.put(`/hosts/${id}`, host);
    return res.data.data;
  },

  delete: async (id: string): Promise<void> => {
    await api.delete(`/hosts/${id}`);
  },
};
```

## Router Configuration (React Router v7)

**File: `main.tsx`**

```typescript
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { Refine } from "@refinedev/core";
import { RefineKbar, RefineKbarProvider } from "@refinedev/kbar";
import routerBindings from "@refinedev/react-router-v7";
import { LoginPage } from "./pages/login";
import { DashboardPage } from "./pages/dashboard";
import { HostsPage } from "./pages/hosts";
import { LayoutComponent } from "./components/Layout";
import { useAuthStore } from "./hooks/useAuth";

export const App: React.FC = () => {
  const { token } = useAuthStore();

  return (
    <RefineKbarProvider>
      <BrowserRouter>
        <Refine
          routerProvider={routerBindings}
          dataProvider={dataProvider} // Your data provider
        >
          <Routes>
            <Route
              path="/login"
              element={<LoginPage />}
              index
            />
            <Route element={<LayoutComponent />}>
              <Route path="/dashboard" element={<DashboardPage />} />
              <Route path="/hosts" element={<HostsPage />} />
              {/* More routes */}
              <Route path="*" element={<Navigate to="/dashboard" />} />
            </Route>
          </Routes>
          <RefineKbar />
        </Refine>
      </BrowserRouter>
    </RefineKbarProvider>
  );
};
```

## Vite Configuration

**File: `vite.config.ts`**

```typescript
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5174,
    proxy: {
      "/api": {
        target: "http://localhost:9527",
        changeOrigin: true,
      },
      "/ws": {
        target: "ws://localhost:9527",
        ws: true,
      },
    },
  },
  build: {
    outDir: "../../target/admin-ui-dist",
    emptyOutDir: true,
    rollupOptions: {
      output: {
        manualChunks: {
          react: ["react", "react-dom"],
          antd: ["antd"],
          charts: ["@ant-design/plots"],
          refine: ["@refinedev/core", "@refinedev/antd"],
        },
      },
    },
  },
});
```

## Development Workflow

```bash
# Install dependencies
cd web/admin-panel
npm install

# Development server (http://localhost:5174)
npm run dev

# Type check
npm run type-check

# Build for production
npm run build

# Embedded in binary
cd ../..
cargo build --release
# Binary includes admin-ui-dist/ as static assets
```

## Performance Optimization

- **Code splitting**: Smart Vite/Rollup chunking (React, Ant Design, charts, Refine vendor chunks)
- **Lazy loading**: Routes via React.lazy() or Refine's code-split integration
- **Caching**: Browser caching for static assets, React Query for server state
- **Bundle size**: ~250KB gzipped (uncompressed: ~750KB with Ant Design)

## Accessibility (Ant Design Native)

- ARIA labels built-in via Ant Design components
- Keyboard navigation (Tab, Enter, Escape) handled by Ant Design
- Color not sole indicator: icons + text labels
- High contrast: Ant Design theme respects WCAG AA

## Browser Support

- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+
- ES2020+ (no IE11 support)
