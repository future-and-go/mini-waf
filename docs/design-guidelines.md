# Admin UI Design Guidelines

## Technology Stack

- **Vue 3** (3.3.13) — Composition API + setup syntax
- **TypeScript** (5.3) — Full type safety
- **Vite** (5.1.3) — Dev server (hot reload) + production bundler
- **Tailwind CSS** (3.4.1) — Utility-first styling
- **Pinia** (2.1.7) — State management (replaces Vuex)
- **Vue Router** (4.2.5) — Client-side routing (hash mode: `#/page`)
- **Axios** (1.6) — HTTP client with interceptors
- **vue-i18n** (9.14.5) — Internationalization (11 locales)
- **lucide-vue-next** (0.577) — Icon library
- **Vite Plugin Vue** — Single-file component compilation

## Project Structure

```
web/admin-ui/
├── src/
│   ├── main.ts               # Entry point
│   ├── App.vue               # Root component
│   │
│   ├── views/                # Page components (21 views)
│   │   ├── Dashboard.vue
│   │   ├── Login.vue
│   │   ├── Hosts.vue
│   │   ├── IpRules.vue
│   │   ├── UrlRules.vue
│   │   ├── CustomRules.vue
│   │   ├── SecurityEvents.vue
│   │   ├── AttackLogs.vue
│   │   ├── Certificates.vue
│   │   ├── RulesManagement.vue
│   │   ├── Notifications.vue
│   │   ├── CrowdSecSettings.vue
│   │   ├── CrowdSecDecisions.vue
│   │   ├── CrowdSecStats.vue
│   │   ├── ClusterOverview.vue
│   │   ├── ClusterNodeDetail.vue
│   │   ├── ClusterTokens.vue
│   │   ├── ClusterSync.vue
│   │   ├── BotDetection.vue
│   │   ├── SensitivePatterns.vue
│   │   └── CCProtection.vue
│   │
│   ├── components/           # Reusable components (5 core)
│   │   ├── Layout.vue        # Main sidebar + header
│   │   ├── StatCard.vue      # Metric card (RPS, blocked %, etc.)
│   │   ├── RuleTable.vue     # Reusable rule listing + pagination
│   │   ├── Badge.vue         # Status badges (healthy, warning, error)
│   │   └── NavItem.vue       # Sidebar navigation item
│   │
│   ├── stores/               # Pinia state management
│   │   └── auth.ts           # User, JWT token, TOTP
│   │
│   ├── api/                  # API client modules (11 modules)
│   │   ├── index.ts          # Axios instance + interceptors
│   │   ├── auth.ts           # Login, logout, refresh
│   │   ├── hosts.ts          # Host CRUD
│   │   ├── rules.ts          # Rule enable/disable
│   │   ├── ipRules.ts        # IP allow/block CRUD
│   │   ├── urlRules.ts       # URL pattern CRUD
│   │   ├── certificates.ts   # TLS cert management
│   │   ├── events.ts         # Security event queries
│   │   ├── stats.ts          # Metrics + time-series
│   │   ├── cluster.ts        # Cluster API
│   │   └── notifications.ts  # Alert channel CRUD
│   │
│   ├── i18n/                 # Internationalization
│   │   ├── index.ts          # vue-i18n config
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
│   ├── router/               # Vue Router config
│   │   └── index.ts          # Routes + navigation guards
│   │
│   ├── types/                # TypeScript interfaces
│   │   ├── api.ts            # API response types
│   │   ├── domain.ts         # Business domain types
│   │   └── index.ts
│   │
│   └── styles/
│       └── globals.css       # Global Tailwind + custom CSS
│
├── package.json
├── vite.config.ts
├── tsconfig.json
└── README.md
```

## Component Patterns

### 1. Layout Shell

**File: `components/Layout.vue`**

```vue
<template>
  <div class="flex h-screen bg-gray-900 text-white">
    <!-- Sidebar -->
    <aside class="w-64 bg-gray-800 border-r border-gray-700">
      <nav class="space-y-2 p-4">
        <NavItem to="/dashboard" icon="Home" label="Dashboard" />
        <NavItem to="/hosts" icon="Globe" label="Hosts" />
        <NavItem to="/rules" icon="Zap" label="Rules" />
        <!-- More items -->
      </nav>
    </aside>

    <!-- Main Content -->
    <main class="flex-1 overflow-auto">
      <!-- Header -->
      <header class="bg-gray-800 border-b border-gray-700 p-4">
        <h1 class="text-2xl font-bold">{{ pageTitle }}</h1>
      </header>

      <!-- Page Content (slot) -->
      <div class="p-6">
        <slot />
      </div>
    </main>
  </div>
</template>

<script setup lang="ts">
import NavItem from './NavItem.vue'
const pageTitle = ref('Dashboard')
</script>

<style scoped>
/* Tailwind handles styling */
</style>
```

### 2. StatCard Component

**File: `components/StatCard.vue`**

```vue
<template>
  <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
    <div class="flex items-center justify-between">
      <div>
        <p class="text-sm text-gray-400">{{ label }}</p>
        <p class="text-3xl font-bold mt-2">{{ value }}</p>
        <p v-if="change" :class="changeClass" class="text-sm mt-1">
          {{ change }}
        </p>
      </div>
      <div class="text-gray-600">
        <component :is="icon" :size="32" />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

interface Props {
  label: string
  value: string | number
  change?: string
  trend?: 'up' | 'down'
  icon?: any
}

const props = withDefaults(defineProps<Props>(), {
  trend: 'up',
})

const changeClass = computed(() =>
  props.trend === 'up' ? 'text-green-400' : 'text-red-400'
)
</script>
```

### 3. RuleTable Component

**File: `components/RuleTable.vue`**

```vue
<template>
  <div class="space-y-4">
    <!-- Filters -->
    <div class="flex gap-4">
      <input
        v-model="searchQuery"
        type="text"
        placeholder="Search rules..."
        class="flex-1 px-4 py-2 bg-gray-700 rounded text-white"
      />
      <select
        v-model="filterCategory"
        class="px-4 py-2 bg-gray-700 rounded text-white"
      >
        <option value="">All Categories</option>
        <option value="xss">XSS</option>
        <option value="sqli">SQL Injection</option>
      </select>
    </div>

    <!-- Table -->
    <table class="w-full border-collapse">
      <thead class="bg-gray-700 border-b border-gray-600">
        <tr>
          <th class="px-4 py-2 text-left">ID</th>
          <th class="px-4 py-2 text-left">Name</th>
          <th class="px-4 py-2 text-left">Category</th>
          <th class="px-4 py-2 text-center">Enabled</th>
          <th class="px-4 py-2 text-right">Actions</th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="rule in filteredRules"
          :key="rule.id"
          class="border-b border-gray-700 hover:bg-gray-700"
        >
          <td class="px-4 py-2 font-mono text-sm">{{ rule.id }}</td>
          <td class="px-4 py-2">{{ rule.name }}</td>
          <td class="px-4 py-2">
            <Badge :label="rule.category" :color="categoryColor(rule.category)" />
          </td>
          <td class="px-4 py-2 text-center">
            <input
              v-model="rule.enabled"
              type="checkbox"
              @change="onToggle(rule)"
            />
          </td>
          <td class="px-4 py-2 text-right space-x-2">
            <button @click="onEdit(rule)" class="text-blue-400 hover:text-blue-300">
              Edit
            </button>
            <button @click="onDelete(rule)" class="text-red-400 hover:text-red-300">
              Delete
            </button>
          </td>
        </tr>
      </tbody>
    </table>

    <!-- Pagination -->
    <div class="flex justify-between items-center">
      <span class="text-sm text-gray-400">
        Page {{ currentPage }} of {{ totalPages }}
      </span>
      <div class="space-x-2">
        <button
          @click="currentPage--"
          :disabled="currentPage === 1"
          class="px-4 py-2 bg-blue-600 rounded disabled:opacity-50"
        >
          Previous
        </button>
        <button
          @click="currentPage++"
          :disabled="currentPage === totalPages"
          class="px-4 py-2 bg-blue-600 rounded disabled:opacity-50"
        >
          Next
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import Badge from './Badge.vue'

interface Rule {
  id: string
  name: string
  category: string
  enabled: boolean
}

interface Props {
  rules: Rule[]
  onToggle: (rule: Rule) => Promise<void>
  onEdit: (rule: Rule) => void
  onDelete: (rule: Rule) => Promise<void>
}

defineProps<Props>()

const searchQuery = ref('')
const filterCategory = ref('')
const currentPage = ref(1)
const pageSize = 20

const filteredRules = computed(() => {
  return props.rules
    .filter(r => r.name.includes(searchQuery.value))
    .filter(r => !filterCategory.value || r.category === filterCategory.value)
    .slice((currentPage.value - 1) * pageSize, currentPage.value * pageSize)
})

const totalPages = computed(() =>
  Math.ceil(props.rules.length / pageSize)
)

const categoryColor = (category: string) => {
  const colors: Record<string, string> = {
    xss: 'red',
    sqli: 'orange',
    rce: 'red',
    scanner: 'yellow',
  }
  return colors[category] || 'gray'
}
</script>
```

### 4. Badge Component

**File: `components/Badge.vue`**

```vue
<template>
  <span :class="[baseClass, colorClass]">
    {{ label }}
  </span>
</template>

<script setup lang="ts">
import { computed } from 'vue'

interface Props {
  label: string
  color?: 'red' | 'yellow' | 'green' | 'blue' | 'gray'
  variant?: 'solid' | 'outline'
}

const props = withDefaults(defineProps<Props>(), {
  color: 'gray',
  variant: 'solid',
})

const baseClass = 'px-3 py-1 rounded-full text-xs font-semibold'

const colorClass = computed(() => {
  const colors = {
    solid: {
      red: 'bg-red-600 text-white',
      yellow: 'bg-yellow-600 text-white',
      green: 'bg-green-600 text-white',
      blue: 'bg-blue-600 text-white',
      gray: 'bg-gray-600 text-white',
    },
    outline: {
      red: 'border border-red-500 text-red-500',
      yellow: 'border border-yellow-500 text-yellow-500',
      green: 'border border-green-500 text-green-500',
      blue: 'border border-blue-500 text-blue-500',
      gray: 'border border-gray-500 text-gray-500',
    },
  }
  return colors[props.variant][props.color]
})
</script>
```

### 5. NavItem Component

**File: `components/NavItem.vue`**

```vue
<template>
  <router-link
    :to="to"
    :class="[
      'flex items-center gap-3 px-4 py-2 rounded-lg transition',
      isActive
        ? 'bg-blue-600 text-white'
        : 'text-gray-300 hover:bg-gray-700',
    ]"
  >
    <component :is="icon" :size="20" />
    <span>{{ label }}</span>
  </router-link>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'

interface Props {
  to: string
  icon: any
  label: string
}

defineProps<Props>()

const route = useRoute()

const isActive = computed(() =>
  route.path.startsWith(props.to)
)
</script>
```

## View Examples

### Dashboard View

**File: `views/Dashboard.vue`**

```vue
<template>
  <Layout>
    <div class="space-y-6">
      <!-- Stats Row -->
      <div class="grid grid-cols-4 gap-6">
        <StatCard
          label="Requests/sec"
          :value="stats.rps"
          trend="up"
          :change="`+${stats.rpsChange}% vs last hour`"
          :icon="TrendingUp"
        />
        <StatCard
          label="Blocked"
          :value="stats.blockedCount"
          :change="`${stats.blockedPercent}% blocked`"
          :icon="Shield"
        />
        <StatCard
          label="Active Rules"
          :value="stats.activeRules"
          :icon="Zap"
        />
        <StatCard
          label="Cluster Nodes"
          :value="stats.clusterNodes"
          :icon="Network"
        />
      </div>

      <!-- Charts -->
      <div class="grid grid-cols-2 gap-6">
        <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <h3 class="text-lg font-semibold mb-4">Traffic Over Time</h3>
          <!-- Chart component here -->
        </div>
        <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <h3 class="text-lg font-semibold mb-4">Top Rules</h3>
          <RuleTable :rules="topRules" />
        </div>
      </div>

      <!-- Recent Events -->
      <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <h3 class="text-lg font-semibold mb-4">Recent Attacks</h3>
        <div class="space-y-2">
          <div v-for="event in recentEvents" :key="event.id" class="flex items-center justify-between">
            <span>{{ event.rule }} ({{ event.ip }})</span>
            <Badge :label="event.severity" :color="severityColor(event.severity)" />
          </div>
        </div>
      </div>
    </div>
  </Layout>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { TrendingUp, Shield, Zap, Network } from 'lucide-vue-next'
import Layout from '../components/Layout.vue'
import StatCard from '../components/StatCard.vue'
import RuleTable from '../components/RuleTable.vue'
import Badge from '../components/Badge.vue'
import * as api from '../api'

const stats = ref({
  rps: 1250,
  rpsChange: 12,
  blockedCount: 342,
  blockedPercent: 5.2,
  activeRules: 48,
  clusterNodes: 3,
})

const topRules = ref([])
const recentEvents = ref([])

onMounted(async () => {
  topRules.value = await api.stats.getTopRules()
  recentEvents.value = await api.events.getRecent(10)
})

const severityColor = (severity: string) => {
  const colors = { critical: 'red', high: 'orange', medium: 'yellow', low: 'blue' }
  return colors[severity] || 'gray'
}
</script>
```

## i18n Key Conventions

All translation keys use dot notation:

```typescript
// locales/en.ts
export default {
  common: {
    save: 'Save',
    cancel: 'Cancel',
    delete: 'Delete',
    edit: 'Edit',
  },
  nav: {
    dashboard: 'Dashboard',
    hosts: 'Hosts',
    rules: 'Rules',
  },
  pages: {
    dashboard: {
      title: 'Dashboard',
      stats: {
        rps: 'Requests per Second',
        blocked: 'Blocked Requests',
      },
    },
  },
  errors: {
    notFound: 'Page not found',
    unauthorized: 'Unauthorized',
    serverError: 'Server error',
  },
}
```

**Usage in templates:**
```vue
<h1>{{ $t('pages.dashboard.title') }}</h1>
<button>{{ $t('common.save') }}</button>
```

## API Client Patterns

### Axios Instance with Interceptors

**File: `api/index.ts`**

```typescript
import axios, { AxiosInstance } from 'axios'
import { useAuth } from '../stores/auth'

const api: AxiosInstance = axios.create({
  baseURL: '/api',
  timeout: 15000,
})

// Request interceptor: add JWT
api.interceptors.request.use((config) => {
  const auth = useAuth()
  if (auth.token) {
    config.headers.Authorization = `Bearer ${auth.token}`
  }
  return config
})

// Response interceptor: auto-logout on 401
api.interceptors.response.use(
  response => response,
  (error) => {
    if (error.response?.status === 401) {
      useAuth().logout()
      location.href = '/#/login'
    }
    return Promise.reject(error)
  }
)

export default api
```

### API Module Pattern

**File: `api/hosts.ts`**

```typescript
import api from './index'

export interface Host {
  id: string
  name: string
  upstreamUrl: string
  enabled: boolean
}

export const hosts = {
  list: async (): Promise<Host[]> => {
    const res = await api.get('/hosts')
    return res.data
  },

  get: async (id: string): Promise<Host> => {
    const res = await api.get(`/hosts/${id}`)
    return res.data
  },

  create: async (host: Omit<Host, 'id'>): Promise<Host> => {
    const res = await api.post('/hosts', host)
    return res.data
  },

  update: async (id: string, host: Partial<Host>): Promise<Host> => {
    const res = await api.put(`/hosts/${id}`, host)
    return res.data
  },

  delete: async (id: string): Promise<void> => {
    await api.delete(`/hosts/${id}`)
  },
}
```

## Router Configuration

**File: `router/index.ts`**

```typescript
import { createRouter, createWebHashHistory } from 'vue-router'
import { useAuth } from '../stores/auth'

const routes = [
  {
    path: '/',
    redirect: '/dashboard',
  },
  {
    path: '/login',
    component: () => import('../views/Login.vue'),
    meta: { requiresAuth: false },
  },
  {
    path: '/dashboard',
    component: () => import('../views/Dashboard.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/hosts',
    component: () => import('../views/Hosts.vue'),
    meta: { requiresAuth: true },
  },
  // More routes...
]

const router = createRouter({
  history: createWebHashHistory(),
  routes,
})

// Navigation guard
router.beforeEach((to, from, next) => {
  const auth = useAuth()
  
  if (to.meta.requiresAuth && !auth.isLoggedIn) {
    next('/login')
  } else {
    next()
  }
})

export default router
```

## Vite Configuration

**File: `vite.config.ts`**

```typescript
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:9527',
        changeOrigin: true,
      },
      '/ws': {
        target: 'ws://localhost:9527',
        ws: true,
      },
    },
  },
  build: {
    outDir: '../../../target/admin-ui-dist',
    emptyOutDir: true,
  },
})
```

## Development Workflow

```bash
# Install dependencies
cd web/admin-ui
npm install

# Development server (http://localhost:5173)
npm run dev

# Build for production
npm run build

# Embedded in binary
cd ../..
cargo build --release
# Binary includes admin-ui-dist/ as static assets
```

## Performance Optimization

- **Code splitting**: Routes lazy-loaded via `() => import()`
- **Asset optimization**: Tailwind CSS purges unused styles
- **Caching**: Vue components cached by Vite
- **Bundle size**: ~200KB gzipped (uncompressed: ~600KB)

## Accessibility

- ARIA labels on form inputs
- Keyboard navigation (Tab, Enter, Escape)
- Color not the only indicator (icons + text)
- Sufficient contrast (Tailwind colors meet WCAG AA)

## Browser Support

- Chrome 90+
- Firefox 88+
- Safari 15+
- Edge 90+
- ES2020+ (no IE11 support)
