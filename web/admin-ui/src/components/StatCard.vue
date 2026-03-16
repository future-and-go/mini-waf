<template>
  <div class="bg-white rounded-xl shadow-sm p-4">
    <p class="text-xs text-gray-500 font-medium">{{ label }}</p>
    <p :class="colorClass" class="text-2xl font-bold mt-1">{{ value }}</p>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ label: string; value: any; color?: string }>()

const colorClass = computed(() => {
  const map: Record<string, string> = {
    blue: 'text-blue-600',
    red: 'text-red-600',
    green: 'text-green-600',
    purple: 'text-purple-600',
  }
  return map[props.color || 'blue'] || 'text-gray-800'
})
</script>
