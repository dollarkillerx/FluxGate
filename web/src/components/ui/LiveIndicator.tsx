import { useI18n } from '@/i18n/I18nContext'

/** Subtle "auto-refreshing" indicator (pulsing green dot + label). */
export function LiveIndicator({ seconds }: { seconds: number }) {
  const { t } = useI18n()
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full border border-slate-200 px-2.5 py-1 text-xs text-slate-500 dark:border-slate-700 dark:text-slate-400"
      title={t('common.autoRefresh', { s: seconds })}
    >
      <span className="relative flex h-2 w-2">
        <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
        <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
      </span>
      {t('common.live')}
    </span>
  )
}
