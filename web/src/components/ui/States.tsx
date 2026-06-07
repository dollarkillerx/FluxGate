import type { ReactNode } from 'react'
import { Loader2, AlertCircle, Inbox } from 'lucide-react'
import { Button } from './Button'
import { useI18n } from '@/i18n/I18nContext'

export function Spinner({ label }: { label?: string }) {
  const { t } = useI18n()
  return (
    <div className="flex items-center justify-center gap-2 py-10 text-sm text-slate-500 dark:text-slate-400">
      <Loader2 size={18} className="animate-spin text-brand-500" />
      {label ?? t('common.loading')}
    </div>
  )
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  const { t } = useI18n()
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-10 text-center">
      <AlertCircle size={28} className="text-red-500" />
      <div>
        <p className="text-sm font-medium text-slate-700 dark:text-slate-200">{t('common.errorTitle')}</p>
        <p className="mt-1 max-w-md text-xs text-slate-500 dark:text-slate-400">{message}</p>
      </div>
      {onRetry && (
        <Button variant="secondary" size="sm" onClick={onRetry}>
          {t('common.retry')}
        </Button>
      )}
    </div>
  )
}

export function EmptyState({ message, icon }: { message: string; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-10 text-center">
      <div className="text-slate-300 dark:text-slate-600">{icon ?? <Inbox size={28} />}</div>
      <p className="text-sm text-slate-500 dark:text-slate-400">{message}</p>
    </div>
  )
}

interface StateViewProps<T> {
  loading: boolean
  error: string | null
  data: T | null
  onRetry?: () => void
  children: (data: T) => ReactNode
}

/** Renders loading / error / data branches for an async resource. */
export function StateView<T>({ loading, error, data, onRetry, children }: StateViewProps<T>) {
  const { t } = useI18n()
  if (loading && data === null) return <Spinner />
  if (error && data === null) return <ErrorState message={error} onRetry={onRetry} />
  if (data === null) return <EmptyState message={t('common.noData')} />
  return <>{children(data)}</>
}
