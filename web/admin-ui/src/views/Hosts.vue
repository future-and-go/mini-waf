<template>
  <Layout>
    <div class="p-6">
      <div class="flex items-center justify-between mb-6">
        <h2 class="text-xl font-semibold text-gray-800">{{ $t('hosts.title') }}</h2>
        <button @click="showForm = true" class="btn-primary">{{ $t('hosts.addHost') }}</button>
      </div>

      <!-- Add form -->
      <div v-if="showForm" class="bg-white rounded-xl shadow-sm p-4 mb-6">
        <h3 class="text-sm font-semibold mb-3">{{ $t('hosts.newHost') }}</h3>
        <div class="grid grid-cols-2 gap-3">
          <input v-model="form.host" :placeholder="$t('hosts.hostname')" class="input" />
          <input v-model.number="form.port" :placeholder="$t('hosts.port')" type="number" class="input" />
          <input v-model="form.remote_host" :placeholder="$t('hosts.upstream')" class="input" />
          <input v-model.number="form.remote_port" placeholder="Upstream port" type="number" class="input" />
          <input v-model="form.remarks" :placeholder="$t('hosts.remarks')" class="input col-span-2" />
        </div>
        <div class="flex gap-3 mt-3">
          <label class="flex items-center gap-1 text-sm"><input type="checkbox" v-model="form.ssl" /> {{ $t('hosts.ssl') }}</label>
          <label class="flex items-center gap-1 text-sm"><input type="checkbox" v-model="form.guard_status" /> {{ $t('hosts.guard') }}</label>
          <label class="flex items-center gap-1 text-sm"><input type="checkbox" v-model="form.start_status" checked /> {{ $t('hosts.start') }}</label>
        </div>
        <div class="flex gap-2 mt-3">
          <button @click="createHost" class="btn-primary text-sm">{{ $t('common.create') }}</button>
          <button @click="showForm = false" class="btn-secondary text-sm">{{ $t('common.cancel') }}</button>
        </div>
      </div>

      <!-- Table -->
      <div class="bg-white rounded-xl shadow-sm overflow-hidden">
        <table class="w-full text-sm">
          <thead class="bg-gray-50 border-b">
            <tr>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('hosts.hostname') }}</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('hosts.upstream') }}</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('hosts.ssl') }}</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('hosts.guard') }}</th>
              <th class="text-left px-4 py-3 font-medium text-gray-600">{{ $t('hosts.status') }}</th>
              <th class="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-100">
            <tr v-for="h in hosts" :key="h.id" class="hover:bg-gray-50">
              <td class="px-4 py-3 font-mono">{{ h.host }}:{{ h.port }}</td>
              <td class="px-4 py-3 font-mono text-gray-500">{{ h.remote_host }}:{{ h.remote_port }}</td>
              <td class="px-4 py-3"><Badge :active="h.ssl" :yes="$t('hosts.ssl')" :no="$t('hosts.http')" /></td>
              <td class="px-4 py-3"><Badge :active="h.guard_status" :yes="$t('hosts.on')" :no="$t('hosts.off')" /></td>
              <td class="px-4 py-3"><Badge :active="h.start_status" :yes="$t('hosts.active')" :no="$t('hosts.stopped')" /></td>
              <td class="px-4 py-3 text-right">
                <button @click="deleteHost(h.id)" class="text-red-500 hover:text-red-700 text-xs">{{ $t('common.delete') }}</button>
              </td>
            </tr>
            <tr v-if="!hosts.length">
              <td colspan="6" class="px-4 py-6 text-center text-gray-400 text-sm">{{ $t('hosts.noHosts') }}</td>
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
import { useI18n } from 'vue-i18n'
import Layout from '../components/Layout.vue'
import Badge from '../components/Badge.vue'

const { t } = useI18n()
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
  if (!confirm(t('hosts.confirmDelete'))) return
  await hostsApi.delete(id)
  load()
}

onMounted(load)
</script>

<style scoped>
.input { @apply border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500; }
.btn-primary { @apply bg-blue-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-blue-700 disabled:opacity-50; }
.btn-secondary { @apply bg-white text-gray-700 border border-gray-300 px-4 py-2 rounded-md text-sm font-medium hover:bg-gray-50; }
</style>
