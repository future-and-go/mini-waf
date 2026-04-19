<template>
  <div class="w-full">
    <svg v-if="points.length" :viewBox="`0 0 ${W} ${H}`" class="w-full h-48" preserveAspectRatio="none">
      <!-- Y grid -->
      <g stroke="#f1f5f9" stroke-width="1">
        <line v-for="i in 4" :key="i" :x1="0" :y1="(i * H / 4)" :x2="W" :y2="(i * H / 4)" />
      </g>

      <!-- Total area -->
      <path :d="totalArea" fill="#3b82f6" fill-opacity="0.12" />
      <path :d="totalLine" fill="none" stroke="#3b82f6" stroke-width="2" />

      <!-- Blocked line -->
      <path :d="blockedLine" fill="none" stroke="#ef4444" stroke-width="2" />

      <!-- Data points -->
      <g>
        <circle v-for="(p, i) in points" :key="`t${i}`" :cx="x(i)" :cy="y(p.total)" r="2.5" fill="#3b82f6" />
        <circle v-for="(p, i) in points" :key="`b${i}`" :cx="x(i)" :cy="y(p.blocked)" r="2.5" fill="#ef4444" />
      </g>
    </svg>
    <div v-else class="h-48 flex items-center justify-center text-sm text-gray-400">
      No traffic data yet
    </div>

    <!-- X axis labels -->
    <div v-if="points.length" class="flex justify-between text-xs text-gray-400 mt-2 px-1">
      <span>{{ fmtTime(points[0].ts) }}</span>
      <span v-if="points.length > 2">{{ fmtTime(points[Math.floor(points.length / 2)].ts) }}</span>
      <span>{{ fmtTime(points[points.length - 1].ts) }}</span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

interface TsPoint { ts: string; total: number; blocked: number }
const props = defineProps<{ series: TsPoint[] }>()

const W = 1000
const H = 180
const PAD = 10

const points = computed(() => props.series ?? [])

const maxY = computed(() => {
  if (!points.value.length) return 1
  const m = Math.max(...points.value.map(p => Number(p.total) || 0), 1)
  return Math.ceil(m * 1.1)
})

function x(i: number): number {
  const n = points.value.length
  if (n <= 1) return W / 2
  return PAD + (i / (n - 1)) * (W - 2 * PAD)
}
function y(v: number): number {
  return H - PAD - (Number(v) / maxY.value) * (H - 2 * PAD)
}

const totalLine = computed(() => buildPath(points.value.map((p, i) => [x(i), y(p.total)])))
const blockedLine = computed(() => buildPath(points.value.map((p, i) => [x(i), y(p.blocked)])))
const totalArea = computed(() => {
  if (!points.value.length) return ''
  const top = points.value.map((p, i) => `${i === 0 ? 'M' : 'L'}${x(i)},${y(p.total)}`).join(' ')
  return `${top} L${x(points.value.length - 1)},${H - PAD} L${x(0)},${H - PAD} Z`
})

function buildPath(pts: number[][]): string {
  if (!pts.length) return ''
  return pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${p[0]},${p[1]}`).join(' ')
}

function fmtTime(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
}
</script>
