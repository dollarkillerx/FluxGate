import { createContext, useCallback, useContext, useState, type ReactNode } from 'react'
import { CheckCircle2, AlertTriangle, XCircle, Info, X } from 'lucide-react'

type ToastTone = 'success' | 'error' | 'warning' | 'info'

interface Toast {
  id: number
  tone: ToastTone
  title: string
  message?: string
}

interface ToastCtx {
  push: (t: Omit<Toast, 'id'>) => void
  success: (title: string, message?: string) => void
  error: (title: string, message?: string) => void
  warning: (title: string, message?: string) => void
  info: (title: string, message?: string) => void
}

const Ctx = createContext<ToastCtx | null>(null)

let counter = 0

const toneStyles: Record<ToastTone, { icon: ReactNode; ring: string }> = {
  success: { icon: <CheckCircle2 size={18} className="text-emerald-500" />, ring: 'border-l-emerald-500' },
  error: { icon: <XCircle size={18} className="text-red-500" />, ring: 'border-l-red-500' },
  warning: { icon: <AlertTriangle size={18} className="text-amber-500" />, ring: 'border-l-amber-500' },
  info: { icon: <Info size={18} className="text-brand-500" />, ring: 'border-l-brand-500' },
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])

  const remove = useCallback((id: number) => {
    setToasts((list) => list.filter((t) => t.id !== id))
  }, [])

  const push = useCallback(
    (t: Omit<Toast, 'id'>) => {
      const id = ++counter
      setToasts((list) => [...list, { ...t, id }])
      setTimeout(() => remove(id), 4500)
    },
    [remove],
  )

  const api: ToastCtx = {
    push,
    success: (title, message) => push({ tone: 'success', title, message }),
    error: (title, message) => push({ tone: 'error', title, message }),
    warning: (title, message) => push({ tone: 'warning', title, message }),
    info: (title, message) => push({ tone: 'info', title, message }),
  }

  return (
    <Ctx.Provider value={api}>
      {children}
      <div className="pointer-events-none fixed bottom-5 right-5 z-[100] flex w-80 flex-col gap-2.5">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={`pointer-events-auto flex items-start gap-3 rounded-md border border-l-4 border-slate-200 bg-white p-3.5 shadow-flyout dark:border-slate-700 dark:bg-slate-800 ${toneStyles[t.tone].ring}`}
            role="status"
          >
            <div className="mt-0.5 shrink-0">{toneStyles[t.tone].icon}</div>
            <div className="min-w-0 flex-1">
              <p className="text-sm font-semibold text-slate-800 dark:text-slate-100">{t.title}</p>
              {t.message && <p className="mt-0.5 break-words text-xs text-slate-500 dark:text-slate-400">{t.message}</p>}
            </div>
            <button
              onClick={() => remove(t.id)}
              className="shrink-0 rounded p-0.5 text-slate-400 hover:bg-slate-100 hover:text-slate-600 dark:hover:bg-slate-700"
              aria-label="Dismiss"
            >
              <X size={15} />
            </button>
          </div>
        ))}
      </div>
    </Ctx.Provider>
  )
}

export function useToast() {
  const ctx = useContext(Ctx)
  if (!ctx) throw new Error('useToast must be used within ToastProvider')
  return ctx
}
