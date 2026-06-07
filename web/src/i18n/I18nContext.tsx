import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { DEFAULT_LOCALE, messages, type Locale } from './locales'

const STORAGE_KEY = 'fluxgate.locale'

/** Signature of the translate function returned by `useI18n`. */
export type Translate = (key: string, vars?: Record<string, string | number>) => string

interface I18nCtx {
  locale: Locale
  setLocale: (l: Locale) => void
  /** Translate a key, with optional `{var}` interpolation. */
  t: Translate
}

const Ctx = createContext<I18nCtx | null>(null)

/** Resolve the initial locale: saved choice → system language → English. */
export function detectLocale(): Locale {
  const saved = localStorage.getItem(STORAGE_KEY)
  if (saved === 'en' || saved === 'zh' || saved === 'ja') return saved

  const candidates = [navigator.language, ...(navigator.languages ?? [])]
  for (const lang of candidates) {
    const code = lang.toLowerCase()
    if (code.startsWith('zh')) return 'zh'
    if (code.startsWith('ja')) return 'ja'
    if (code.startsWith('en')) return 'en'
  }
  return DEFAULT_LOCALE
}

function interpolate(template: string, vars?: Record<string, string | number>): string {
  if (!vars) return template
  return template.replace(/\{(\w+)\}/g, (_, k) => (k in vars ? String(vars[k]) : `{${k}}`))
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(() => detectLocale())

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, locale)
    document.documentElement.lang = locale
  }, [locale])

  const setLocale = useCallback((l: Locale) => setLocaleState(l), [])

  const t = useCallback(
    (key: string, vars?: Record<string, string | number>) => {
      // Fall back to English, then to the raw key if a translation is missing.
      const value = messages[locale][key] ?? messages.en[key] ?? key
      return interpolate(value, vars)
    },
    [locale],
  )

  const value = useMemo(() => ({ locale, setLocale, t }), [locale, setLocale, t])

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useI18n() {
  const ctx = useContext(Ctx)
  if (!ctx) throw new Error('useI18n must be used within I18nProvider')
  return ctx
}
