<template>
  <Layout>
    <div class="p-6">
      <h2 class="text-xl font-semibold text-gray-800 mb-6">CC Protection &amp; Rate Limiting</h2>

      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <!-- LB Backends -->
        <div class="bg-white rounded-xl shadow-sm p-4">
          <div class="flex items-center justify-between mb-3">
            <h3 class="text-sm font-semibold text-gray-700">Load Balancer Backends</h3>
            <button @click="showBackendForm = !showBackendForm" class="text-xs text-blue-600">+ Add</button>
          </div>

          <div v-if="showBackendForm" class="flex gap-2 mb-3">
            <input v-model="backendForm.backend_host" placeholder="Host" class="input flex-1 text-sm" />
            <input v-model.number="backendForm.backend_port" placeholder="Port" type="number" class="input w-20 text-sm" />
            <input v-model="backendForm.host_code" placeholder="Host code" class="input w-32 text-sm" />
            <button @click="addBackend" class="btn-primary text-xs">Add</button>
          </div>

          <div class="space-y-1">
            <div v-for="b in backends" :key="b.id"
                 class="flex items-center justify-between text-xs bg-gray-50 rounded px-2 py-1.5">
              <span class="font-mono">{{ b.backend_host }}:{{ b.backend_port }}</span>
              <div class="flex items-center gap-2">
                <span :class="b.is_healthy ? 'text-green-600' : 'text-red-500'">
                  {{ b.is_healthy ? '● Healthy' : '○ Unhealthy' }}
                </span>
                <button @click="deleteBackend(b.id)" class="text-red-500">✕</button>
              </div>
            </div>
            <p v-if="!backends.length" class="text-xs text-gray-400 text-center py-2">No backends</p>
          </div>
        </div>

        <!-- Hotlink Config -->
        <div class="bg-white rounded-xl shadow-sm p-4">
          <h3 class="text-sm font-semibold text-gray-700 mb-3">Anti-Hotlink Config</h3>
          <div class="space-y-3">
            <input v-model="hotlinkForm.host_code" placeholder="Host code" class="input text-sm w-full" />
            <div class="flex items-center gap-3">
              <label class="flex items-center gap-1 text-sm">
                <input type="checkbox" v-model="hotlinkForm.enabled" />
                Enabled
              </label>
              <label class="flex items-center gap-1 text-sm">
                <input type="checkbox" v-model="hotlinkForm.allow_empty_referer" />
                Allow empty referer
              </label>
            </div>
            <input v-model="hotlinkForm.redirect_url" placeholder="Redirect URL (optional)" class="input text-sm w-full" />
            <button @click="saveHotlink" class="btn-primary text-sm">Save</button>
          </div>
        </div>
      </div>
    </div>
  </Layout>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { ccApi } from '../api'
import Layout from '../components/Layout.vue'

const backends = ref<any[]>([])
const showBackendForm = ref(false)
const backendForm = ref({ host_code: '', backend_host: '', backend_port: 8080 })
const hotlinkForm = ref({ host_code: '', enabled: true, allow_empty_referer: true, redirect_url: '' })

async function load() {
  const r = await ccApi.listBackends()
  backends.value = r.data.data
}

async function addBackend() {
  await ccApi.createBackend(backendForm.value)
  load()
}

async function deleteBackend(id: string) {
  await ccApi.deleteBackend(id)
  load()
}

async function saveHotlink() {
  await ccApi.upsertHotlink(hotlinkForm.value)
  alert('Hotlink config saved')
}

onMounted(load)
</script>
