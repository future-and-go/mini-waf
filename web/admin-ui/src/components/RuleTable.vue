<template>
  <div class="bg-white rounded-xl shadow-sm p-4">
    <div class="flex items-center justify-between mb-3">
      <h3 class="text-sm font-semibold" :class="color === 'green' ? 'text-green-700' : 'text-red-700'">
        {{ title }}
      </h3>
      <button @click="showAdd = !showAdd" class="text-xs text-blue-600 hover:text-blue-800">+ Add</button>
    </div>

    <!-- Add form -->
    <div v-if="showAdd" class="flex gap-2 mb-3">
      <input v-model="newValue" :placeholder="fieldLabel" class="input flex-1 text-sm" />
      <input v-model="newHostCode" placeholder="Host code (optional)" class="input text-sm w-40" />
      <button @click="addRow" class="btn-primary text-xs">Add</button>
    </div>

    <!-- List -->
    <div class="space-y-1 max-h-80 overflow-y-auto">
      <div
        v-for="row in rows"
        :key="row.id"
        class="flex items-center justify-between text-xs bg-gray-50 rounded px-2 py-1.5"
      >
        <span class="font-mono">{{ row[fieldKey] }}</span>
        <div class="flex items-center gap-2 text-gray-400">
          <span>{{ row.host_code }}</span>
          <button @click="$emit('delete', row.id)" class="text-red-500 hover:text-red-700">✕</button>
        </div>
      </div>
      <p v-if="!rows.length" class="text-xs text-gray-400 text-center py-2">Empty</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'

const props = defineProps<{
  title: string
  color: 'green' | 'red'
  rows: any[]
  fieldLabel: string
  fieldKey: string
  hostCode?: string
}>()

const emit = defineEmits<{
  add: [data: any]
  delete: [id: string]
}>()

const showAdd = ref(false)
const newValue = ref('')
const newHostCode = ref(props.hostCode || '')

function addRow() {
  if (!newValue.value) return
  emit('add', { [props.fieldKey]: newValue.value, host_code: newHostCode.value || '*' })
  newValue.value = ''
  showAdd.value = false
}
</script>
