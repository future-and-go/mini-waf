<template>
  <router-link
    :to="to"
    class="flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-colors"
    :class="isActive
      ? 'bg-blue-600 text-white'
      : 'text-gray-300 hover:bg-gray-700 hover:text-white'"
  >
    <span>{{ icon }}</span>
    <slot />
  </router-link>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'

const props = defineProps<{ to: string; icon: string }>()
const route = useRoute()
const isActive = computed(() => route.path === props.to)
</script>
