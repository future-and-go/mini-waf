<template>
  <Layout>
    <div class="p-6">
      <h2 class="text-xl font-semibold text-gray-800 mb-6">Security Events</h2>

      <!-- Filters -->
      <div class="flex gap-3 mb-4 flex-wrap">
        <input v-model="filter.host_code" @change="load" placeholder="Host code" class="input text-sm w-40" />
        <input v-model="filter.client_ip" @change="load" placeholder="Client IP" class="input text-sm w-40" />
        <select v-model="filter.action" @change="load" class="input text-sm w-32">
          <option value="">All actions</option>
          <option value="block">Block</option>
          <option value="allow">Allow</option>
        </select>
        <button @click="load" class="btn-primary text-sm">Filter</button>
      </div>

      <!-- Table -->
      <div class="bg-white rounded-xl shadow-sm overflow-hidden">
        <table class="w-full text-sm">
          <thead class="bg-gray-50 border-b">
            <tr>
              <th class="text-left px-4 py-3 font-medium text-gray-600">Time</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">IP</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">Method</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">Path</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">Rule</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">Action</th>
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
              <td colspan="6" class="px-4 py-6 text-center text-gray-400">No events</td>
            </tr>
          </tbody>
        </table>
        <!-- Pagination -->
        <div class="px-4 py-3 border-t flex items-center justify-between text-sm text-gray-500">
          <span>Total: {{ total }}</span>
          <div class="flex gap-2">
            <button @click="page--; load()" :disabled="page <= 1" class="btn-secondary text-xs">Prev</button>
            <span>{{ page }}</span>
            <button @click="page++; load()" :disabled="page * 20 >= total" class="btn-secondary text-xs">Next</button>
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
