import { useLocation } from 'react-router-dom'
import { Moon, Sun, Search, Bell, RefreshCw, LogOut } from 'lucide-react'
import { NAV_ITEMS } from './nav'
import { useTheme } from '@/context/ThemeContext'
import { useToast } from '@/context/ToastContext'
import { useAuth } from '@/context/AuthContext'
import { useI18n } from '@/i18n/I18nContext'
import { rpc } from '@/api/rpc'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { LanguageSwitcher } from '@/components/ui/LanguageSwitcher'
import { useState } from 'react'

export function Header() {
  const { theme, toggle } = useTheme()
  const toast = useToast()
  const { user, logout } = useAuth()
  const { t } = useI18n()
  const location = useLocation()
  const [reloadOpen, setReloadOpen] = useState(false)

  const initials = (user ?? 'admin').slice(0, 2).toUpperCase()

  const current = NAV_ITEMS.find((n) => (n.to === '/' ? location.pathname === '/' : location.pathname.startsWith(n.to)))

  const reload = async () => {
    try {
      const res = await rpc.call<{ message: string }>('system.reload')
      toast.success(t('header.reload.success'), res.message)
    } catch (e: any) {
      toast.error(t('header.reload.failed'), e?.message)
    }
  }

  return (
    <header className="flex h-14 shrink-0 items-center justify-between gap-4 border-b border-slate-200 bg-white px-6 dark:border-slate-800 dark:bg-slate-900">
      <div className="flex items-center gap-2 text-sm">
        <span className="text-slate-400">FluxGate</span>
        <span className="text-slate-300 dark:text-slate-600">/</span>
        <span className="font-medium text-slate-700 dark:text-slate-200">{t(current?.labelKey ?? 'nav.dashboard')}</span>
      </div>

      <div className="flex items-center gap-1.5">
        <div className="relative mr-2 hidden md:block">
          <Search size={15} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            placeholder={t('common.search')}
            className="focus-ring h-9 w-56 rounded-md border border-slate-300 bg-slate-50 pl-8 pr-3 text-sm placeholder:text-slate-400 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-100"
          />
        </div>

        <LanguageSwitcher className="mr-1 hidden sm:inline-flex" />

        <button
          onClick={() => setReloadOpen(true)}
          title={t('header.reloadTitle')}
          className="focus-ring grid h-9 w-9 place-items-center rounded-md text-slate-500 hover:bg-slate-100 hover:text-slate-700 dark:hover:bg-slate-800 dark:hover:text-slate-200"
        >
          <RefreshCw size={17} />
        </button>

        <button
          title={t('header.notifications')}
          className="focus-ring relative grid h-9 w-9 place-items-center rounded-md text-slate-500 hover:bg-slate-100 hover:text-slate-700 dark:hover:bg-slate-800 dark:hover:text-slate-200"
        >
          <Bell size={17} />
          <span className="absolute right-2 top-2 h-1.5 w-1.5 rounded-full bg-red-500" />
        </button>

        <button
          onClick={toggle}
          title={t('header.toggleTheme')}
          className="focus-ring grid h-9 w-9 place-items-center rounded-md text-slate-500 hover:bg-slate-100 hover:text-slate-700 dark:hover:bg-slate-800 dark:hover:text-slate-200"
        >
          {theme === 'dark' ? <Sun size={17} /> : <Moon size={17} />}
        </button>

        <div className="ml-2 flex items-center gap-2.5 border-l border-slate-200 pl-3 dark:border-slate-700">
          <div className="grid h-8 w-8 place-items-center rounded-full bg-brand-600 text-xs font-semibold text-white">{initials}</div>
          <div className="hidden leading-tight sm:block">
            <div className="text-xs font-medium text-slate-700 dark:text-slate-200">{user ?? 'admin'}</div>
            <div className="text-[10px] text-slate-400">{t('common.administrator')}</div>
          </div>
          <button
            onClick={logout}
            title={t('common.signOut')}
            className="focus-ring ml-1 grid h-9 w-9 place-items-center rounded-md text-slate-500 hover:bg-slate-100 hover:text-red-600 dark:hover:bg-slate-800"
          >
            <LogOut size={17} />
          </button>
        </div>
      </div>

      <ConfirmDialog
        open={reloadOpen}
        onClose={() => setReloadOpen(false)}
        onConfirm={reload}
        tone="primary"
        title={t('header.reload.title')}
        confirmLabel={t('header.reload.confirm')}
        message={t('header.reload.message')}
      />
    </header>
  )
}
