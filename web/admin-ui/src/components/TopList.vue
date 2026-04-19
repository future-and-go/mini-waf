<template>
  <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
    <div class="flex items-center gap-2 mb-3">
      <component v-if="icon" :is="icon" class="w-4 h-4 text-gray-400" />
      <h3 class="text-sm font-semibold text-gray-800">{{ title }}</h3>
    </div>
    <div v-if="items?.length" class="space-y-1.5">
      <div
        v-for="item in items.slice(0, 10)"
        :key="item.key"
        class="flex items-center justify-between gap-3 group"
      >
        <div class="flex-1 min-w-0 relative">
          <div
            class="absolute inset-y-0 left-0 bg-gray-100 rounded-sm group-hover:bg-gray-200 transition-colors"
            :style="{ width: pct(item.count) + '%' }"
          />
          <div class="relative px-2 py-1 text-sm truncate" :class="mono ? 'font-mono text-xs' : ''">
            {{ item.key }}
          </div>
        </div>
        <span :class="badgeClass" class="text-xs font-medium px-2 py-0.5 rounded tabular-nums shrink-0">
          {{ fmt(item.count) }}
        </span>
      </div>
    </div>
    <p v-else class="text-sm text-gray-400">No data</p>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { Component } from 'vue'

interface TopEntry { key: string; count: number }

const props = defineProps<{
  title: string
  items: TopEntry[] | undefined
  icon?: Component
  badgeClass?: string
  mono?: boolean
}>()

const max = computed(() => {
  if (!props.items?.length) return 1
  return Math.max(...props.items.map(i => Number(i.count) || 0), 1)
})

function pct(n: number): number {
  return (Number(n) / max.value) * 100
}
function fmt(n: number): string {
  return new Intl.NumberFormat().format(Number(n))
}
</script>
