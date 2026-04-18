<template>
  <Layout>
    <div class="p-6">
      <h2 class="text-xl font-semibold text-gray-800 mb-6">{{ $t('settings.title') }}</h2>

      <!-- Status card -->
      <div class="bg-white rounded-xl shadow-sm p-4 mb-6">
        <h3 class="text-sm font-semibold text-gray-700 mb-3">{{ $t('settings.systemStatus') }}</h3>
        <div v-if="status" class="grid grid-cols-2 gap-4 text-sm">
          <div>
            <p class="text-gray-500">{{ $t('settings.version') }}</p>
            <p class="font-medium">{{ status.version }}</p>
          </div>
          <div>
            <p class="text-gray-500">{{ $t('settings.activeHosts') }}</p>
            <p class="font-medium">{{ status.hosts }}</p>
          </div>
          <div>
            <p class="text-gray-500">{{ $t('settings.totalRequests') }}</p>
            <p class="font-medium">{{ status.total_requests }}</p>
          </div>
          <div>
            <p class="text-gray-500">{{ $t('settings.rules') }}</p>
            <p class="font-medium">
              IPs: {{ status.rules?.allow_ips + status.rules?.block_ips }}
              / URLs: {{ status.rules?.allow_urls + status.rules?.block_urls }}
            </p>
          </div>
        </div>
        <div class="mt-4 flex gap-3">
          <button @click="loadStatus" class="btn-secondary text-sm">{{ $t('common.refresh') }}</button>
          <button @click="reloadRules" class="btn-primary text-sm">{{ $t('settings.reloadRules') }}</button>
        </div>
      </div>

      <!-- Info -->
      <div class="bg-white rounded-xl shadow-sm p-4">
        <h3 class="text-sm font-semibold text-gray-700 mb-3">{{ $t('settings.configuration') }}</h3>
        <div class="space-y-2 text-sm text-gray-600">
          <p>API endpoint: <code class="bg-gray-100 px-1 rounded">http://&lt;host&gt;:9527</code></p>
          <p>Admin UI: <code class="bg-gray-100 px-1 rounded">http://&lt;host&gt;:9527/ui/</code></p>
          <p>WebSocket events: <code class="bg-gray-100 px-1 rounded">ws://&lt;host&gt;:9527/ws/events</code> <span class="text-gray-400">(protocol: bearer.JWT)</span></p>
          <p>WebSocket logs: <code class="bg-gray-100 px-1 rounded">ws://&lt;host&gt;:9527/ws/logs</code> <span class="text-gray-400">(protocol: bearer.JWT)</span></p>
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
import { useI18n } from 'vue-i18n'
import Layout from '../components/Layout.vue'

const { t } = useI18n()
const status = ref<any>(null)

async function loadStatus() {
  const r = await systemApi.status()
  status.value = r.data.data
}

async function reloadRules() {
  await systemApi.reload()
  alert(t('settings.rulesReloaded'))
}

onMounted(loadStatus)
</script>

<style scoped>
.btn-primary { @apply bg-blue-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-blue-700; }
.btn-secondary { @apply bg-white text-gray-700 border border-gray-300 px-4 py-2 rounded-md text-sm font-medium hover:bg-gray-50; }
</style>
