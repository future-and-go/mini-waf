<template>
  <div
    :class="enabled ? 'border-green-200 bg-green-50' : 'border-gray-200 bg-gray-50 opacity-60'"
    class="border rounded-lg px-3 py-2 flex items-start gap-2"
  >
    <span
      :class="enabled ? 'bg-green-500' : 'bg-gray-400'"
      class="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0"
    />
    <div class="min-w-0">
      <p class="text-xs font-semibold text-gray-800 truncate">{{ name }}</p>
      <p class="text-[11px] text-gray-500 truncate" :title="description">{{ description }}</p>
    </div>
  </div>
</template>

<script setup lang="ts">
defineProps<{ name: string; description: string; enabled: boolean }>()
</script>
