import { useEffect, useMemo, useRef, useState } from 'react'
import { Search, X, Check, ChevronDown } from 'lucide-react'
import { useI18n } from '@/i18n/I18nContext'
import { flag } from '@/lib/utils'

/** ISO 3166-1 alpha-2 country codes. Names are resolved per-locale via Intl. */
const ISO_CODES = [
  'AD','AE','AF','AG','AI','AL','AM','AO','AR','AT','AU','AW','AZ','BA','BB','BD','BE','BF','BG','BH','BI','BJ','BN','BO','BR','BS','BT','BW','BY','BZ',
  'CA','CD','CF','CG','CH','CI','CL','CM','CN','CO','CR','CU','CV','CY','CZ','DE','DJ','DK','DM','DO','DZ','EC','EE','EG','ER','ES','ET','FI','FJ','FM',
  'FR','GA','GB','GD','GE','GH','GM','GN','GQ','GR','GT','GW','GY','HK','HN','HR','HT','HU','ID','IE','IL','IN','IQ','IR','IS','IT','JM','JO','JP','KE',
  'KG','KH','KI','KM','KN','KP','KR','KW','KZ','LA','LB','LC','LI','LK','LR','LS','LT','LU','LV','LY','MA','MC','MD','ME','MG','MH','MK','ML','MM','MN',
  'MO','MR','MT','MU','MV','MW','MX','MY','MZ','NA','NE','NG','NI','NL','NO','NP','NR','NZ','OM','PA','PE','PG','PH','PK','PL','PT','PW','PY','QA','RO',
  'RS','RU','RW','SA','SB','SC','SD','SE','SG','SI','SK','SL','SM','SN','SO','SR','SS','ST','SV','SY','SZ','TD','TG','TH','TJ','TL','TM','TN','TO','TR',
  'TT','TV','TW','TZ','UA','UG','US','UY','UZ','VA','VC','VE','VN','VU','WS','YE','ZA','ZM','ZW',
]

interface Props {
  value: string[]
  onChange: (codes: string[]) => void
  placeholder?: string
}

/** Searchable, multi-select country picker. Stores ISO alpha-2 codes. */
export function CountryMultiSelect({ value, onChange, placeholder }: Props) {
  const { locale } = useI18n()
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const ref = useRef<HTMLDivElement>(null)

  const countries = useMemo(() => {
    let dn: Intl.DisplayNames | null = null
    try {
      dn = new Intl.DisplayNames([locale], { type: 'region' })
    } catch {
      dn = null
    }
    return ISO_CODES.map((code) => ({ code, name: dn?.of(code) ?? code })).sort((a, b) =>
      a.name.localeCompare(b.name),
    )
  }, [locale])

  const nameOf = (code: string) => countries.find((c) => c.code === code)?.name ?? code

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return countries
    return countries.filter((c) => c.code.toLowerCase().includes(q) || c.name.toLowerCase().includes(q))
  }, [countries, query])

  useEffect(() => {
    if (!open) return
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDoc)
    return () => document.removeEventListener('mousedown', onDoc)
  }, [open])

  const toggle = (code: string) =>
    onChange(value.includes(code) ? value.filter((c) => c !== code) : [...value, code])

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex min-h-[2.5rem] w-full flex-wrap items-center gap-1.5 rounded-md border border-slate-300 bg-white px-2 py-1.5 text-left text-sm dark:border-slate-600 dark:bg-slate-800"
      >
        {value.length === 0 ? (
          <span className="px-1 text-slate-400">{placeholder ?? 'Select countries…'}</span>
        ) : (
          value.map((code) => (
            <span
              key={code}
              className="inline-flex items-center gap-1 rounded bg-slate-100 py-0.5 pl-1.5 pr-1 text-xs dark:bg-slate-700"
            >
              <span className="text-sm leading-none">{flag(code)}</span>
              <span className="font-medium">{code}</span>
              <span
                role="button"
                tabIndex={-1}
                onClick={(e) => {
                  e.stopPropagation()
                  toggle(code)
                }}
                className="rounded p-0.5 text-slate-400 hover:bg-slate-200 hover:text-slate-600 dark:hover:bg-slate-600"
              >
                <X size={11} />
              </span>
            </span>
          ))
        )}
        <ChevronDown size={15} className="ml-auto shrink-0 text-slate-400" />
      </button>

      {open && (
        <div className="absolute z-30 mt-1 w-full overflow-hidden rounded-md border border-slate-200 bg-white shadow-lg dark:border-slate-700 dark:bg-slate-800">
          <div className="flex items-center gap-2 border-b border-slate-100 px-2.5 py-2 dark:border-slate-700">
            <Search size={14} className="text-slate-400" />
            <input
              autoFocus
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search country or code…"
              className="w-full bg-transparent text-sm outline-none placeholder:text-slate-400"
            />
          </div>
          <div className="max-h-56 overflow-auto py-1">
            {filtered.length === 0 ? (
              <div className="px-3 py-4 text-center text-xs text-slate-400">No match</div>
            ) : (
              filtered.map((c) => {
                const sel = value.includes(c.code)
                return (
                  <button
                    key={c.code}
                    type="button"
                    onClick={() => toggle(c.code)}
                    className="flex w-full items-center justify-between gap-2 px-3 py-1.5 text-left text-sm hover:bg-slate-50 dark:hover:bg-slate-700/60"
                  >
                    <span className="flex min-w-0 items-center gap-2">
                      <span className="text-base leading-none">{flag(c.code)}</span>
                      <span className="truncate text-slate-700 dark:text-slate-200">{nameOf(c.code)}</span>
                      <span className="shrink-0 font-mono text-xs text-slate-400">{c.code}</span>
                    </span>
                    {sel && <Check size={15} className="shrink-0 text-brand-500" />}
                  </button>
                )
              })
            )}
          </div>
        </div>
      )}
    </div>
  )
}
