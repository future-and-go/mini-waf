<template>
  <Layout>
    <div class="p-6">
      <h2 class="text-xl font-semibold text-gray-800 mb-6">Dashboard</h2>

      <!-- Stats cards -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard label="Total Requests" :value="stats.total_requests_live ?? '-'" color="blue" />
        <StatCard label="Blocked" :value="stats.total_blocked ?? '-'" color="red" />
        <StatCard label="Allowed" :value="stats.total_allowed ?? '-'" color="green" />
        <StatCard label="Hosts" :value="stats.hosts_count ?? '-'" color="purple" />
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <!-- Top IPs -->
        <div class="bg-white rounded-xl shadow-sm p-4">
          <h3 class="text-sm font-semibold text-gray-700 mb-3">Top Attacking IPs</h3>
          <div v-if="stats.top_ips?.length" class="space-y-2">
            <div
              v-for="item in stats.top_ips"
              :key="item.key"
              class="flex items-center justify-between text-sm"
            >
              <span class="font-mono text-gray-700">{{ item.key }}</span>
              <span class="bg-red-100 text-red-700 px-2 py-0.5 rounded text-xs font-medium">{{ item.count }}</span>
            </div>
          </div>
          <p v-else class="text-sm text-gray-400">No data</p>
        </div>

        <!-- Top Rules -->
        <div class="bg-white rounded-xl shadow-sm p-4">
          <h3 class="text-sm font-semibold text-gray-700 mb-3">Top Triggered Rules</h3>
          <div v-if="stats.top_rules?.length" class="space-y-2">
            <div
              v-for="item in stats.top_rules"
              :key="item.key"
              class="flex items-center justify-between text-sm"
            >
              <span class="text-gray-700">{{ item.key }}</span>
              <span class="bg-orange-100 text-orange-700 px-2 py-0.5 rounded text-xs font-medium">{{ item.count }}</span>
            </div>
          </div>
          <p v-else class="text-sm text-gray-400">No data</p>
        </div>
      </div>

      <!-- Live Events -->
      <div class="bg-white rounded-xl shadow-sm p-4 mt-6">
        <div class="flex items-center justify-between mb-3">
          <h3 class="text-sm font-semibold text-gray-700">Live Security Events</h3>
          <span :class="wsConnected ? 'text-green-600' : 'text-gray-400'" class="text-xs font-medium">
            {{ wsConnected ? '● Live' : '○ Disconnected' }}
          </span>
        </div>
        <div class="space-y-1 max-h-64 overflow-y-auto">
          <div
            v-for="(ev, i) in liveEvents"
            :key="i"
            class="text-xs font-mono text-gray-600 bg-gray-50 rounded px-2 py-1"
          >
            {{ JSON.stringify(ev) }}
          </div>
          <p v-if="!liveEvents.length" class="text-xs text-gray-400">Waiting for events...</p>
        </div>
      </div>
    </div>
  </Layout>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { statsApi } from '../api'
import { useAuthStore } from '../stores/auth'
import Layout from '../components/Layout.vue'
import StatCard from '../components/StatCard.vue'

const auth = useAuthStore()
const stats = ref<any>({})
const liveEvents = ref<any[]>([])
const wsConnected = ref(false)
let ws: WebSocket | null = null

async function loadStats() {
  try {
    const resp = await statsApi.overview()
    stats.value = resp.data.data
  } catch (_) {}
}

function connectWs() {
  const token = auth.accessToken
  if (!token) return
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  const host = location.host
  ws = new WebSocket(`${proto}://${host}/ws/events?token=${token}`)
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
  loadStats()
  connectWs()
  const interval = setInterval(loadStats, 30000)
  onUnmounted(() => {
    clearInterval(interval)
    ws?.close()
  })
})
</script>
