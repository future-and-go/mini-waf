<template>
  <Layout>
    <div class="p-6">
      <h2 class="text-xl font-semibold text-gray-800 mb-6">{{ $t('security.title') }}</h2>

      <!-- Filters -->
      <div class="flex gap-3 mb-4 flex-wrap">
        <input v-model="filter.host_code" @change="load" :placeholder="$t('security.hostCode')" class="input text-sm w-40" />
        <input v-model="filter.client_ip" @change="load" :placeholder="$t('security.clientIP')" class="input text-sm w-40" />
        <select v-model="filter.action" @change="load" class="input text-sm w-32">
          <option value="">{{ $t('security.allActions') }}</option>
          <option value="block">{{ $t('security.block') }}</option>
          <option value="allow">{{ $t('security.allow') }}</option>
        </select>
        <button @click="load" class="btn-primary text-sm">{{ $t('security.filter') }}</button>
      </div>

      <!-- Table -->
      <div class="bg-white rounded-xl shadow-sm overflow-hidden">
        <table class="w-full text-sm">
          <thead class="bg-gray-50 border-b">
            <tr>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('security.time') }}</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('security.clientIP') }}</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('security.method') }}</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('security.path') }}</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('security.ruleName') }}</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('security.action') }}</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-100">
            <tr v-for="e in events" :key="e.id" class="hover:bg-gray-50">
              <td class="px-4 py-3 text-gray-400 text-xs">{{ fmtTime(e.created_at) }}</td>
              <td class="px-4 py-3 font-mono">{{ e.client_ip }}</td>
              <td class="px-4 py-3 font-mono">{{ e.method }}</td>
              <td class="px-4 py-3 font-mono text-gray-600 max-w-xs truncate">{{ e.path }}</td>
              <td class="px-4 py-3 text-gray-600">{{ e.rule_name }}</td>
              <td class="px-4 py-3">
                <span :class="e.action === 'block' ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700'"
                      class="text-xs px-2 py-0.5 rounded font-medium">{{ e.action }}</span>
              </td>
            </tr>
            <tr v-if="!events.length">
              <td colspan="6" class="px-4 py-6 text-center text-gray-400">{{ $t('security.noEvents') }}</td>
            </tr>
          </tbody>
        </table>
        <!-- Pagination -->
        <div class="px-4 py-3 border-t flex items-center justify-between text-sm text-gray-500">
          <span>{{ $t('common.total') }}: {{ total }}</span>
          <div class="flex gap-2">
            <button @click="page--; load()" :disabled="page <= 1" class="btn-secondary text-xs">{{ $t('common.prev') }}</button>
            <span>{{ page }}</span>
            <button @click="page++; load()" :disabled="page * 20 >= total" class="btn-secondary text-xs">{{ $t('common.next') }}</button>
          </div>
        </div>
      </div>
    </div>
  </Layout>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { eventsApi } from '../api'
import Layout from '../components/Layout.vue'

const events = ref<any[]>([])
const total = ref(0)
const page = ref(1)
const filter = ref({ host_code: '', client_ip: '', action: '' })

async function load() {
  const r = await eventsApi.listSecurityEvents({ ...filter.value, page: page.value, page_size: 20 })
  events.value = r.data.data
  total.value = r.data.total
}

function fmtTime(ts: string) {
  return new Date(ts).toLocaleString()
}

onMounted(load)
</script>

<style scoped>
.input { @apply border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500; }
.btn-primary { @apply bg-blue-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-blue-700; }
.btn-secondary { @apply bg-white text-gray-700 border border-gray-300 px-4 py-2 rounded-md text-sm font-medium hover:bg-gray-50 disabled:opacity-50; }
</style>
