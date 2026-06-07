import { useState, type FormEvent } from 'react'
import { Lock, User, AlertCircle } from 'lucide-react'
import { useAuth } from '@/context/AuthContext'
import { useI18n } from '@/i18n/I18nContext'
import { Button } from '@/components/ui/Button'
import { LanguageSwitcher } from '@/components/ui/LanguageSwitcher'

export function Login() {
  const { login } = useAuth()
  const { t } = useI18n()
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      await login(username, password)
    } catch (err: any) {
      // session.ts throws translation keys; t() falls back to the raw message.
      setError(t(err?.message ?? 'login.failed'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-slate-100 to-slate-200 px-4 dark:from-slate-950 dark:to-slate-900">
      <div className="w-full max-w-sm">
        {/* Top bar: language selector */}
        <div className="mb-4 flex justify-end">
          <LanguageSwitcher />
        </div>

        {/* Brand */}
        <div className="mb-6 flex flex-col items-center gap-3">
          <div className="grid h-12 w-12 place-items-center rounded-xl bg-brand-600 text-white shadow-card">
            <svg viewBox="0 0 32 32" className="h-7 w-7" fill="none">
              <path d="M9 9h14M9 16h9M9 23h14" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round" />
              <circle cx="23" cy="16" r="2.6" fill="currentColor" />
            </svg>
          </div>
          <div className="text-center">
            <h1 className="text-xl font-semibold text-slate-800 dark:text-white">FluxGate</h1>
            <p className="text-xs uppercase tracking-wider text-slate-400">{t('app.subtitle')}</p>
          </div>
        </div>

        <form onSubmit={submit} className="panel space-y-4 p-6">
          <div>
            <h2 className="text-base font-semibold text-slate-800 dark:text-slate-100">{t('login.signIn')}</h2>
            <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">{t('login.subtitle')}</p>
          </div>

          {error && (
            <div className="flex items-start gap-2 rounded-md bg-red-50 px-3 py-2 text-xs text-red-600 dark:bg-red-500/10 dark:text-red-400">
              <AlertCircle size={15} className="mt-0.5 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <label className="block space-y-1.5">
            <span className="text-xs font-medium text-slate-600 dark:text-slate-300">{t('login.username')}</span>
            <div className="relative">
              <User size={15} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                className="focus-ring h-9 w-full rounded-md border border-slate-300 bg-white pl-8 pr-3 text-sm dark:border-slate-600 dark:bg-slate-800 dark:text-slate-100"
                placeholder="admin"
              />
            </div>
          </label>

          <label className="block space-y-1.5">
            <span className="text-xs font-medium text-slate-600 dark:text-slate-300">{t('login.password')}</span>
            <div className="relative">
              <Lock size={15} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                className="focus-ring h-9 w-full rounded-md border border-slate-300 bg-white pl-8 pr-3 text-sm dark:border-slate-600 dark:bg-slate-800 dark:text-slate-100"
                placeholder="••••••••"
              />
            </div>
          </label>

          <Button type="submit" className="w-full" loading={busy}>
            {t('login.signIn')}
          </Button>

          <p className="rounded-md bg-slate-50 px-3 py-2 text-center text-xs text-slate-500 dark:bg-slate-800/50 dark:text-slate-400">
            {t('login.demo')} — <span className="font-medium text-slate-600 dark:text-slate-300">admin / admin</span>
          </p>
        </form>

        <p className="mt-4 text-center text-xs text-slate-400">FluxGate {t('app.footer')}</p>
      </div>
    </div>
  )
}
