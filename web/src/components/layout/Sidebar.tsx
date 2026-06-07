import { NavLink } from 'react-router-dom'
import { NAV_ITEMS } from './nav'
import { cn } from '@/lib/utils'
import { useI18n } from '@/i18n/I18nContext'

export function Sidebar() {
  const { t } = useI18n()
  return (
    <aside className="flex h-full w-60 shrink-0 flex-col border-r border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
      {/* Brand */}
      <div className="flex h-14 items-center gap-2.5 border-b border-slate-200 px-5 dark:border-slate-800">
        <div className="grid h-8 w-8 place-items-center rounded-md bg-brand-600 text-white">
          <svg viewBox="0 0 32 32" className="h-5 w-5" fill="none">
            <path d="M9 9h14M9 16h9M9 23h14" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round" />
            <circle cx="23" cy="16" r="2.6" fill="currentColor" />
          </svg>
        </div>
        <div className="leading-tight">
          <div className="text-sm font-semibold text-slate-800 dark:text-white">FluxGate</div>
          <div className="text-[10px] uppercase tracking-wider text-slate-400">{t('app.subtitle')}</div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 space-y-0.5 overflow-y-auto px-3 py-4">
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === '/'}
            className={({ isActive }) =>
              cn(
                'group relative flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors',
                isActive
                  ? 'bg-brand-50 text-brand-700 dark:bg-brand-500/10 dark:text-brand-300'
                  : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-100',
              )
            }
          >
            {({ isActive }) => (
              <>
                <span className={cn('absolute left-0 h-5 w-0.5 rounded-r bg-brand-600 transition-opacity', isActive ? 'opacity-100' : 'opacity-0')} />
                <item.icon size={17} className={cn(isActive ? 'text-brand-600 dark:text-brand-400' : 'text-slate-400 group-hover:text-slate-600 dark:group-hover:text-slate-300')} />
                {t(item.labelKey)}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      <div className="border-t border-slate-200 px-5 py-3 text-[11px] text-slate-400 dark:border-slate-800">
        {t('app.footer')}
      </div>
    </aside>
  )
}
