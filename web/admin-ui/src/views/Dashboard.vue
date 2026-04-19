<template>
  <Layout>
    <div class="p-6 space-y-6">
      <!-- Header -->
      <div class="flex items-start justify-between">
        <div>
          <h2 class="text-2xl font-bold text-gray-900">{{ $t('dashboard.title') }}</h2>
          <p class="text-sm text-gray-500 mt-1">{{ $t('dashboard.subtitle') }}</p>
        </div>
        <div class="flex items-center gap-3">
          <span
            :class="wsConnected ? 'text-green-600 bg-green-50 border-green-200' : 'text-gray-400 bg-gray-50 border-gray-200'"
            class="text-xs font-medium border rounded-full px-3 py-1"
          >
            {{ wsConnected ? $t('dashboard.live') : $t('dashboard.disconnected') }}
          </span>
          <button
            @click="loadAll"
            :disabled="loading"
            class="inline-flex items-center gap-1.5 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md px-3 py-1.5 hover:bg-gray-50 disabled:opacity-50"
          >
            <RefreshCw :class="loading ? 'animate-spin' : ''" class="w-4 h-4" />
            {{ $t('dashboard.refresh') }}
          </button>
        </div>
      </div>

      <!-- Primary KPI cards -->
      <div class="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          :label="$t('dashboard.totalRequests')"
          :value="fmtNum(stats.total_requests)"
          :icon="Activity"
          color="blue"
        />
        <KpiCard
          :label="$t('dashboard.blockedRequests')"
          :value="fmtNum(stats.total_blocked)"
          :icon="ShieldAlert"
          color="red"
        />
        <KpiCard
          :label="$t('dashboard.allowedRequests')"
          :value="fmtNum(stats.total_allowed)"
          :icon="ShieldCheck"
          color="green"
        />
        <KpiCard
          :label="$t('dashboard.blockRate')"
          :value="fmtPct(stats.block_rate)"
          :icon="Percent"
          color="orange"
        />
      </div>

      <!-- Secondary KPI cards -->
      <div class="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          :label="$t('dashboard.activeHosts')"
          :value="fmtNum(stats.hosts_count)"
          :icon="Server"
          color="purple"
        />
        <KpiCard
          :label="$t('dashboard.uniqueAttackers')"
          :value="fmtNum(stats.unique_attackers)"
          :icon="Users"
          color="rose"
        />
        <KpiCard
          :label="$t('dashboard.rulesLoaded')"
          :value="fmtNum(ruleStats.total)"
          :icon="Book"
          color="indigo"
        />
        <KpiCard
          :label="$t('dashboard.categories')"
          :value="fmtNum(ruleStats.categories)"
          :icon="Layers"
          color="teal"
        />
      </div>

      <!-- Traffic chart -->
      <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
        <div class="flex items-center justify-between mb-4">
          <h3 class="text-sm font-semibold text-gray-800">{{ $t('dashboard.trafficChart') }}</h3>
          <div class="flex items-center gap-4 text-xs">
            <span class="flex items-center gap-1.5">
              <span class="w-2.5 h-2.5 rounded-sm bg-blue-500"></span>
              {{ $t('dashboard.legitTraffic') }}
            </span>
            <span class="flex items-center gap-1.5">
              <span class="w-2.5 h-2.5 rounded-sm bg-red-500"></span>
              {{ $t('dashboard.blockedTraffic') }}
            </span>
          </div>
        </div>
        <TrafficChart :series="timeseries" />
      </div>

      <!-- Attack categories + Enforcement actions -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
          <h3 class="text-sm font-semibold text-gray-800 mb-4">{{ $t('dashboard.categoryBreakdown') }}</h3>
          <CategoryBars :items="stats.category_breakdown" :colors="categoryColors" />
        </div>
        <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
          <h3 class="text-sm font-semibold text-gray-800 mb-4">{{ $t('dashboard.actionBreakdown') }}</h3>
          <CategoryBars :items="stats.action_breakdown" :colors="actionColors" />
        </div>
      </div>

      <!-- Top IPs + Top Rules -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <TopList
          :title="$t('dashboard.topIPs')"
          :items="stats.top_ips"
          :icon="Globe"
          badge-class="bg-red-100 text-red-700"
          mono
        />
        <TopList
          :title="$t('dashboard.topRules')"
          :items="stats.top_rules"
          :icon="AlertTriangle"
          badge-class="bg-orange-100 text-orange-700"
        />
      </div>

      <!-- Top Countries + Top ISPs -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <TopList
          :title="$t('dashboard.topCountries')"
          :items="stats.top_countries"
          :icon="MapPin"
          badge-class="bg-purple-100 text-purple-700"
        />
        <TopList
          :title="$t('dashboard.topIsps')"
          :items="stats.top_isps"
          :icon="Wifi"
          badge-class="bg-blue-100 text-blue-700"
        />
      </div>

      <!-- Detection engines panel -->
      <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
        <h3 class="text-sm font-semibold text-gray-800 mb-4">{{ $t('dashboard.detectionEngines') }}</h3>
        <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          <EngineBadge
            v-for="eng in engines"
            :key="eng.key"
            :name="eng.name"
            :description="eng.description"
            :enabled="eng.enabled"
          />
        </div>
      </div>

      <!-- Recent events table -->
      <div class="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
        <div class="p-5 border-b border-gray-100">
          <h3 class="text-sm font-semibold text-gray-800">{{ $t('dashboard.recentEvents') }}</h3>
        </div>
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-gray-100 text-sm">
            <thead class="bg-gray-50 text-xs uppercase text-gray-500">
              <tr>
                <th class="px-4 py-2.5 text-left font-medium">{{ $t('dashboard.time') }}</th>
                <th class="px-4 py-2.5 text-left font-medium">{{ $t('dashboard.clientIp') }}</th>
                <th class="px-4 py-2.5 text-left font-medium">{{ $t('dashboard.country') }}</th>
                <th class="px-4 py-2.5 text-left font-medium">{{ $t('dashboard.method') }}</th>
                <th class="px-4 py-2.5 text-left font-medium">{{ $t('dashboard.path') }}</th>
                <th class="px-4 py-2.5 text-left font-medium">{{ $t('dashboard.rule') }}</th>
                <th class="px-4 py-2.5 text-left font-medium">{{ $t('dashboard.category') }}</th>
                <th class="px-4 py-2.5 text-left font-medium">{{ $t('dashboard.action') }}</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-50">
              <tr v-for="(ev, i) in stats.recent_events" :key="i" class="hover:bg-gray-50">
                <td class="px-4 py-2 text-gray-600 whitespace-nowrap">{{ fmtTime(ev.ts) }}</td>
                <td class="px-4 py-2 font-mono text-xs text-gray-800">{{ ev.client_ip }}</td>
                <td class="px-4 py-2 text-gray-600">{{ ev.country || '—' }}</td>
                <td class="px-4 py-2">
                  <span class="text-xs font-semibold text-gray-600">{{ ev.method }}</span>
                </td>
                <td class="px-4 py-2 font-mono text-xs text-gray-700 max-w-xs truncate" :title="ev.path">{{ ev.path }}</td>
                <td class="px-4 py-2 text-gray-700 max-w-xs truncate" :title="ev.rule_name">
                  <span class="font-mono text-xs text-gray-500">{{ ev.rule_id || '—' }}</span>
                </td>
                <td class="px-4 py-2">
                  <span :class="categoryBadgeClass(ev.category)" class="inline-block px-2 py-0.5 rounded text-xs font-medium">{{ ev.category }}</span>
                </td>
                <td class="px-4 py-2">
                  <span :class="actionBadgeClass(ev.action)" class="inline-block px-2 py-0.5 rounded text-xs font-medium">{{ ev.action }}</span>
                </td>
              </tr>
              <tr v-if="!stats.recent_events?.length">
                <td colspan="8" class="px-4 py-10 text-center text-gray-400 text-sm">
                  {{ $t('dashboard.noRecentEvents') }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Live WebSocket events -->
      <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
        <h3 class="text-sm font-semibold text-gray-800 mb-3">{{ $t('dashboard.liveEvents') }}</h3>
        <div class="space-y-1 max-h-64 overflow-y-auto">
          <div
            v-for="(ev, i) in liveEvents"
            :key="i"
            class="text-xs font-mono text-gray-600 bg-gray-50 rounded px-2 py-1 truncate"
          >
            {{ JSON.stringify(ev) }}
          </div>
          <p v-if="!liveEvents.length" class="text-xs text-gray-400">{{ $t('dashboard.waitingEvents') }}</p>
        </div>
      </div>
    </div>
  </Layout>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, onUnmounted } from 'vue'
import {
  Activity, ShieldAlert, ShieldCheck, Percent, Server, Users, Book, Layers,
  Globe, AlertTriangle, MapPin, Wifi, RefreshCw,
} from 'lucide-vue-next'
import api, { statsApi } from '../api'
import { useAuthStore } from '../stores/auth'
import Layout from '../components/Layout.vue'
import KpiCard from '../components/KpiCard.vue'
import TopList from '../components/TopList.vue'
import TrafficChart from '../components/TrafficChart.vue'
import CategoryBars from '../components/CategoryBars.vue'
import EngineBadge from '../components/EngineBadge.vue'

interface TopEntry { key: string; count: number }
interface RecentEvent {
  ts: string
  client_ip: string
  host_code: string
  method: string
  path: string
  rule_id?: string
  rule_name: string
  action: string
  category: string
  country?: string
}
interface Stats {
  total_requests: number
  total_blocked: number
  total_allowed: number
  block_rate: number
  hosts_count: number
  unique_attackers: number
  top_ips: TopEntry[]
  top_rules: TopEntry[]
  top_countries: TopEntry[]
  top_isps: TopEntry[]
  category_breakdown: TopEntry[]
  action_breakdown: TopEntry[]
  recent_events: RecentEvent[]
}
interface TsPoint { ts: string; total: number; blocked: number }

const auth = useAuthStore()
const stats = reactive<Stats>({
  total_requests: 0, total_blocked: 0, total_allowed: 0, block_rate: 0,
  hosts_count: 0, unique_attackers: 0,
  top_ips: [], top_rules: [], top_countries: [], top_isps: [],
  category_breakdown: [], action_breakdown: [], recent_events: [],
})
const timeseries = ref<TsPoint[]>([])
const ruleStats = reactive({ total: 0, enabled: 0, categories: 0 })
const liveEvents = ref<any[]>([])
const wsConnected = ref(false)
const loading = ref(false)
let ws: WebSocket | null = null

const engines = computed(() => [
  { key: 'libinjection', name: 'libinjection', description: 'SQLi & XSS fingerprint', enabled: true },
  { key: 'owasp-crs',    name: 'OWASP CRS',    description: 'Core Rule Set (YAML)',  enabled: true },
  { key: 'rhai',         name: 'Rhai Scripts', description: 'Custom rule engine',     enabled: true },
  { key: 'bot',          name: 'Bot Detection',description: 'UA + behaviour heuristics', enabled: true },
  { key: 'scanner',      name: 'Scanner',      description: 'Nikto / Acunetix / ZAP',   enabled: true },
  { key: 'cc',           name: 'CC / DDoS',    description: 'Token-bucket per IP',      enabled: true },
  { key: 'ssrf',         name: 'SSRF Guard',   description: 'URL + DNS rebinding pin',  enabled: true },
  { key: 'dir-traversal',name: 'Path Traversal', description: 'LFI / RFI detection',    enabled: true },
  { key: 'rce',          name: 'Command Inject', description: 'Shell / exec patterns',  enabled: true },
  { key: 'sensitive',    name: 'Sensitive Data', description: 'Aho-Corasick PII leak',  enabled: true },
  { key: 'hotlink',      name: 'Anti-Hotlink',   description: 'Referer validation',     enabled: true },
  { key: 'geo',          name: 'GeoIP',          description: 'Country allow/deny list', enabled: true },
  { key: 'crowdsec',     name: 'CrowdSec',       description: 'Bouncer + AppSec',       enabled: !!(stats as any).crowdsec_enabled || false },
  { key: 'wasm',         name: 'WASM Plugins',   description: 'wasmtime sandbox',       enabled: true },
  { key: 'modsec',       name: 'ModSecurity',    description: 'SecRule directives',     enabled: true },
])

const categoryColors: Record<string, string> = {
  sqli: 'bg-red-500', xss: 'bg-orange-500', rce: 'bg-rose-600',
  lfi: 'bg-amber-500', rfi: 'bg-amber-600',
  'path-traversal': 'bg-amber-500',
  'php-injection': 'bg-pink-500', 'nodejs-injection': 'bg-lime-500',
  'protocol-enforcement': 'bg-sky-400', 'protocol-attack': 'bg-sky-600',
  scanner: 'bg-violet-500', bot: 'bg-fuchsia-500', 'cc-ddos': 'bg-yellow-500',
  ssrf: 'bg-cyan-500', ssti: 'bg-teal-500', advanced: 'bg-indigo-500',
  'owasp-crs': 'bg-indigo-600', 'data-leakage': 'bg-emerald-500',
  'api-security': 'bg-blue-500', 'mass-assignment': 'bg-blue-600',
  'web-shell': 'bg-red-700', modsecurity: 'bg-violet-600',
  cve: 'bg-red-800', 'geo-blocking': 'bg-purple-500',
  custom: 'bg-slate-600',
  'ip-rule': 'bg-gray-500', 'url-rule': 'bg-slate-500',
  'sensitive-data': 'bg-emerald-600', 'anti-hotlink': 'bg-blue-400',
  other: 'bg-gray-400',
}
const actionColors: Record<string, string> = {
  block: 'bg-red-500', log: 'bg-yellow-500', allow: 'bg-green-500',
  challenge: 'bg-orange-500', redirect: 'bg-blue-500',
}

function fmtNum(n: number | undefined | null): string {
  if (n == null) return '—'
  return new Intl.NumberFormat().format(n)
}
function fmtPct(n: number | undefined | null): string {
  if (n == null) return '—'
  return `${(n * 100).toFixed(2)}%`
}
function fmtTime(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}
function categoryBadgeClass(cat: string): string {
  const bg = categoryColors[cat] ?? 'bg-gray-400'
  return `${bg} text-white`
}
function actionBadgeClass(act: string): string {
  const bg = actionColors[act] ?? 'bg-gray-400'
  return `${bg} text-white`
}

async function loadOverview() {
  try {
    const resp = await statsApi.overview()
    Object.assign(stats, resp.data.data)
  } catch (_) {}
}
async function loadTimeseries() {
  try {
    const resp = await statsApi.timeseries({ hours: 24 })
    timeseries.value = resp.data.data ?? []
  } catch (_) { timeseries.value = [] }
}
async function loadRuleStats() {
  try {
    const { data } = await api.get('/api/rules/registry')
    ruleStats.total = (data.enabled ?? 0) + (data.disabled ?? 0)
    ruleStats.enabled = data.enabled ?? 0
    const cats = new Set<string>((data.rules ?? []).map((r: any) => r.category).filter(Boolean))
    ruleStats.categories = cats.size
  } catch (_) {
    ruleStats.total = 0; ruleStats.enabled = 0; ruleStats.categories = 0
  }
}
async function loadAll() {
  loading.value = true
  try {
    await Promise.all([loadOverview(), loadTimeseries(), loadRuleStats()])
  } finally {
    loading.value = false
  }
}

function connectWs() {
  const token = auth.accessToken
  if (!token) return
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  const host = location.host
  ws = new WebSocket(`${proto}://${host}/ws/events`, [`bearer.${token}`])
  ws.onopen = () => { wsConnected.value = true }
  ws.onclose = () => {
    wsConnected.value = false
    setTimeout(connectWs, 5000)
  }
  ws.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data)
      liveEvents.value.unshift(data)
      if (liveEvents.value.length > 50) liveEvents.value.pop()
    } catch (_) {}
  }
}

onMounted(() => {
  loadAll()
  connectWs()
  const interval = setInterval(loadAll, 30000)
  onUnmounted(() => {
    clearInterval(interval)
    ws?.close()
  })
})
</script>
