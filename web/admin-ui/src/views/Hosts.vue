<template>
  <Layout>
    <div class="p-6">
      <div class="flex items-center justify-between mb-6">
        <h2 class="text-xl font-semibold text-gray-800">Hosts</h2>
        <button @click="showForm = true" class="btn-primary">+ Add Host</button>
      </div>

      <!-- Add form -->
      <div v-if="showForm" class="bg-white rounded-xl shadow-sm p-4 mb-6">
        <h3 class="text-sm font-semibold mb-3">New Host</h3>
        <div class="grid grid-cols-2 gap-3">
          <input v-model="form.host" placeholder="Host (e.g. example.com)" class="input" />
          <input v-model.number="form.port" placeholder="Port (80)" type="number" class="input" />
          <input v-model="form.remote_host" placeholder="Upstream host" class="input" />
          <input v-model.number="form.remote_port" placeholder="Upstream port" type="number" class="input" />
          <input v-model="form.remarks" placeholder="Remarks" class="input col-span-2" />
        </div>
        <div class="flex gap-3 mt-3">
          <label class="flex items-center gap-1 text-sm"><input type="checkbox" v-model="form.ssl" /> SSL</label>
          <label class="flex items-center gap-1 text-sm"><input type="checkbox" v-model="form.guard_status" /> Guard</label>
          <label class="flex items-center gap-1 text-sm"><input type="checkbox" v-model="form.start_status" checked /> Start</label>
        </div>
        <div class="flex gap-2 mt-3">
          <button @click="createHost" class="btn-primary text-sm">Create</button>
          <button @click="showForm = false" class="btn-secondary text-sm">Cancel</button>
        </div>
      </div>

      <!-- Table -->
      <div class="bg-white rounded-xl shadow-sm overflow-hidden">
        <table class="w-full text-sm">
          <thead class="bg-gray-50 border-b">
            <tr>
              <th class="text-left px-4 py-3 font-medium text-gray-600">Host</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">Upstream</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">SSL</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">Guard</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">Status</th>
              <th class="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-100">
            <tr v-for="h in hosts" :key="h.id" class="hover:bg-gray-50">
              <td class="px-4 py-3 font-mono">{{ h.host }}:{{ h.port }}</td>
              <td class="px-4 py-3 font-mono text-gray-500">{{ h.remote_host }}:{{ h.remote_port }}</td>
              <td class="px-4 py-3"><Badge :active="h.ssl" yes="SSL" no="HTTP" /></td>
              <td class="px-4 py-3"><Badge :active="h.guard_status" yes="On" no="Off" /></td>
              <td class="px-4 py-3"><Badge :active="h.start_status" yes="Active" no="Stopped" /></td>
              <td class="px-4 py-3 text-right">
                <button @click="deleteHost(h.id)" class="text-red-500 hover:text-red-700 text-xs">Delete</button>
              </td>
            </tr>
            <tr v-if="!hosts.length">
              <td colspan="6" class="px-4 py-6 text-center text-gray-400 text-sm">No hosts configured</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </Layout>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { hostsApi } from '../api'
import Layout from '../components/Layout.vue'
import Badge from '../components/Badge.vue'

const hosts = ref<any[]>([])
const showForm = ref(false)
const form = ref({
  host: '', port: 80, ssl: false, guard_status: true,
  remote_host: '', remote_port: 8080, start_status: true,
  log_only_mode: false, remarks: '',
})

async function load() {
  const r = await hostsApi.list()
  hosts.value = r.data.data
}

async function createHost() {
  await hostsApi.create(form.value)
  showForm.value = false
  form.value = { host: '', port: 80, ssl: false, guard_status: true, remote_host: '', remote_port: 8080, start_status: true, log_only_mode: false, remarks: '' }
  load()
}

async function deleteHost(id: string) {
  if (!confirm('Delete this host?')) return
  await hostsApi.delete(id)
  load()
}

onMounted(load)
</script>
