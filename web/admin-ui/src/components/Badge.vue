<template>
  <span :class="active ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'"
        class="text-xs px-2 py-0.5 rounded font-medium">
    {{ active ? yes : no }}
  </span>
</template>

<script setup lang="ts">
defineProps<{ active: boolean; yes?: string; no?: string }>()
</script>
