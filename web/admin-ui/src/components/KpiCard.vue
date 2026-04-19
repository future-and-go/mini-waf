<template>
  <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-4">
    <div class="flex items-start justify-between">
      <div class="min-w-0">
        <p class="text-xs text-gray-500 font-medium truncate">{{ label }}</p>
        <p :class="valueClass" class="text-2xl font-bold mt-1 tabular-nums">{{ value }}</p>
      </div>
      <div :class="iconBg" class="w-9 h-9 rounded-lg flex items-center justify-center shrink-0">
        <component :is="icon" :class="iconColor" class="w-5 h-5" />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { Component } from 'vue'

const props = defineProps<{
  label: string
  value: string | number
  icon: Component
  color?: 'blue' | 'red' | 'green' | 'orange' | 'purple' | 'rose' | 'indigo' | 'teal'
}>()

const palette = {
  blue:   { v: 'text-gray-900', bg: 'bg-blue-50',   ic: 'text-blue-600' },
  red:    { v: 'text-gray-900', bg: 'bg-red-50',    ic: 'text-red-600' },
  green:  { v: 'text-gray-900', bg: 'bg-green-50',  ic: 'text-green-600' },
  orange: { v: 'text-gray-900', bg: 'bg-orange-50', ic: 'text-orange-600' },
  purple: { v: 'text-gray-900', bg: 'bg-purple-50', ic: 'text-purple-600' },
  rose:   { v: 'text-gray-900', bg: 'bg-rose-50',   ic: 'text-rose-600' },
  indigo: { v: 'text-gray-900', bg: 'bg-indigo-50', ic: 'text-indigo-600' },
  teal:   { v: 'text-gray-900', bg: 'bg-teal-50',   ic: 'text-teal-600' },
} as const

const valueClass = computed(() => palette[props.color ?? 'blue'].v)
const iconBg = computed(() => palette[props.color ?? 'blue'].bg)
const iconColor = computed(() => palette[props.color ?? 'blue'].ic)
</script>
