<template>
  <Layout>
    <div class="p-6">
      <h2 class="text-xl font-semibold text-gray-800 mb-6">URL Rules</h2>

      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <RuleTable
          title="Allow URLs"
          color="green"
          :rows="allowUrls"
          @add="addAllowUrl"
          @delete="deleteAllowUrl"
          field-label="URL pattern"
          field-key="url_pattern"
        />
        <RuleTable
          title="Block URLs"
          color="red"
          :rows="blockUrls"
          @add="addBlockUrl"
          @delete="deleteBlockUrl"
          field-label="URL pattern"
          field-key="url_pattern"
        />
      </div>
    </div>
  </Layout>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { urlRulesApi } from '../api'
import Layout from '../components/Layout.vue'
import RuleTable from '../components/RuleTable.vue'

const allowUrls = ref<any[]>([])
const blockUrls = ref<any[]>([])

async function load() {
  const [a, b] = await Promise.all([urlRulesApi.listAllow(), urlRulesApi.listBlock()])
  allowUrls.value = a.data.data
  blockUrls.value = b.data.data
}

async function addAllowUrl(data: any) {
  await urlRulesApi.createAllow({ ...data, match_type: 'prefix' })
  load()
}
async function deleteAllowUrl(id: string) { await urlRulesApi.deleteAllow(id); load() }
async function addBlockUrl(data: any) {
  await urlRulesApi.createBlock({ ...data, match_type: 'prefix' })
  load()
}
async function deleteBlockUrl(id: string) { await urlRulesApi.deleteBlock(id); load() }

onMounted(load)
</script>
