import { Globe } from 'lucide-react'
import { useI18n } from '@/i18n/I18nContext'
import { LOCALE_OPTIONS, type Locale } from '@/i18n/locales'
import { cn } from '@/lib/utils'

/** Compact language selector used in the header and on the login screen. */
export function LanguageSwitcher({ className }: { className?: string }) {
  const { locale, setLocale } = useI18n()

  return (
    <div className={cn('relative inline-flex items-center', className)}>
      <Globe size={15} className="pointer-events-none absolute left-2.5 text-slate-400" />
      <select
        value={locale}
        onChange={(e) => setLocale(e.target.value as Locale)}
        aria-label="Language"
        className="focus-ring h-9 cursor-pointer rounded-md border border-slate-300 bg-white pl-8 pr-7 text-sm text-slate-700 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-200"
      >
        {LOCALE_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </div>
  )
}
