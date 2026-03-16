import { createI18n } from 'vue-i18n'
import en from './en'
import zh from './zh'
import ru from './ru'
import ka from './ka'

export const i18n = createI18n({
  legacy: false,
  locale: localStorage.getItem('locale') || 'en',
  fallbackLocale: 'en',
  messages: { en, zh, ru, ka },
})
