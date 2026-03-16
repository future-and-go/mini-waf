<template>
  <Layout>
    <div class="p-6">
      <h2 class="text-xl font-semibold text-gray-800 mb-6">System Settings</h2>

      <!-- Status card -->
      <div class="bg-white rounded-xl shadow-sm p-4 mb-6">
        <h3 class="text-sm font-semibold text-gray-700 mb-3">System Status</h3>
        <div v-if="status" class="grid grid-cols-2 gap-4 text-sm">
          <div>
            <p class="text-gray-500">Version</p>
            <p class="font-medium">{{ status.version }}</p>
          </div>
          <div>
            <p class="text-gray-500">Active Hosts</p>
            <p class="font-medium">{{ status.hosts }}</p>
          </div>
          <div>
            <p class="text-gray-500">Total Requests</p>
            <p class="font-medium">{{ status.total_requests }}</p>
          </div>
          <div>
            <p class="text-gray-500">Rules</p>
            <p class="font-medium">
              IPs: {{ status.rules?.allow_ips + status.rules?.block_ips }}
              / URLs: {{ status.rules?.allow_urls + status.rules?.block_urls }}
            </p>
          </div>
        </div>
        <div class="mt-4 flex gap-3">
          <button @click="loadStatus" class="btn-secondary text-sm">Refresh</button>
          <button @click="reloadRules" class="btn-primary text-sm">Reload Rules</button>
        </div>
      </div>

      <!-- Info -->
      <div class="bg-white rounded-xl shadow-sm p-4">
        <h3 class="text-sm font-semibold text-gray-700 mb-3">Configuration</h3>
        <div class="space-y-2 text-sm text-gray-600">
          <p>API endpoint: <code class="bg-gray-100 px-1 rounded">http://&lt;host&gt;:9527</code></p>
          <p>Admin UI: <code class="bg-gray-100 px-1 rounded">http://&lt;host&gt;:9527/ui/</code></p>
          <p>WebSocket events: <code class="bg-gray-100 px-1 rounded">ws://&lt;host&gt;:9527/ws/events?token=JWT</code></p>
          <p>WebSocket logs: <code class="bg-gray-100 px-1 rounded">ws://&lt;host&gt;:9527/ws/logs?token=JWT</code></p>
          <p class="text-xs text-gray-400 mt-3">
            Set <code class="bg-gray-100 px-1 rounded">JWT_SECRET</code> and
            <code class="bg-gray-100 px-1 rounded">MASTER_KEY</code> environment variables
            for production security.
          </p>
        </div>
      </div>
    </div>
  </Layout>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { systemApi } from '../api'
import Layout from '../components/Layout.vue'

const status = ref<any>(null)

async function loadStatus() {
  const r = await systemApi.status()
  status.value = r.data.data
}

async function reloadRules() {
  await systemApi.reload()
  alert('Rules reloaded')
}

onMounted(loadStatus)
</script>
