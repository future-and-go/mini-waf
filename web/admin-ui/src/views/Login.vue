<template>
  <div class="min-h-screen flex items-center justify-center bg-gray-900">
    <div class="bg-white rounded-xl shadow-xl p-8 w-full max-w-sm">
      <div class="text-center mb-6">
        <h1 class="text-2xl font-bold text-gray-900">{{ $t('auth.loginTitle') }}</h1>
        <p class="text-sm text-gray-500 mt-1">{{ $t('auth.loginSubtitle') }}</p>
      </div>

      <form @submit.prevent="handleLogin" class="space-y-4">
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">{{ $t('auth.username') }}</label>
          <input
            v-model="form.username"
            type="text"
            placeholder="admin"
            required
            class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">{{ $t('auth.password') }}</label>
          <input
            v-model="form.password"
            type="password"
            placeholder="••••••••"
            required
            class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div v-if="error" class="text-red-600 text-sm bg-red-50 rounded p-2">{{ error }}</div>
        <button
          type="submit"
          :disabled="loading"
          class="w-full bg-blue-600 text-white rounded-lg py-2 text-sm font-medium hover:bg-blue-700 disabled:opacity-50 transition-colors"
        >
          {{ loading ? $t('auth.signingIn') : $t('auth.loginButton') }}
        </button>
      </form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth'

const router = useRouter()
const auth = useAuthStore()
const form = ref({ username: '', password: '' })
const loading = ref(false)
const error = ref('')

async function handleLogin() {
  loading.value = true
  error.value = ''
  try {
    await auth.login(form.value.username, form.value.password)
    router.push('/dashboard')
  } catch (e: any) {
    error.value = e.response?.data?.error || e.message || 'Login failed'
  } finally {
    loading.value = false
  }
}
</script>
