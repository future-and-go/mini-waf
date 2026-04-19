<template>
  <div v-if="items?.length" class="space-y-2">
    <div v-for="item in items" :key="item.key" class="flex items-center gap-3">
      <div class="w-32 shrink-0 text-xs text-gray-700 truncate" :title="item.key">{{ item.key }}</div>
      <div class="flex-1 h-5 bg-gray-100 rounded overflow-hidden">
        <div
          :class="colorFor(item.key)"
          class="h-full flex items-center justify-end pr-2 text-[10px] font-medium text-white min-w-[24px]"
          :style="{ width: pct(item.count) + '%' }"
        >
          {{ fmt(item.count) }}
        </div>
      </div>
    </div>
  </div>
  <p v-else class="text-sm text-gray-400">No data</p>
</template>

<script setup lang="ts">
import { computed } from 'vue'

interface TopEntry { key: string; count: number }

const props = defineProps<{ items: TopEntry[] | undefined; colors: Record<string, string> }>()

const max = computed(() => {
  if (!props.items?.length) return 1
  return Math.max(...props.items.map(i => Number(i.count) || 0), 1)
})

function pct(n: number): number {
  return Math.max(4, (Number(n) / max.value) * 100)
}
function fmt(n: number): string {
  return new Intl.NumberFormat().format(Number(n))
}
function colorFor(key: string): string {
  return props.colors[key] ?? 'bg-gray-400'
}
</script>
