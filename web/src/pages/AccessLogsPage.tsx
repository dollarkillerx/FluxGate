import { useMemo, useState } from 'react'
import { createColumnHelper } from '@tanstack/react-table'
import { Search, X } from 'lucide-react'
import { useRpc } from '@/hooks/useRpc'
import { useI18n } from '@/i18n/I18nContext'
import type { AccessLog, Paged, WafAction } from '@/types'
import { PageHeader } from '@/components/ui/PageHeader'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Select } from '@/components/ui/Field'
import { DataTable } from '@/components/ui/DataTable'
import { StateView } from '@/components/ui/States'
import { formatTime } from '@/lib/utils'
import { httpStatusTone, wafActionTone } from '@/lib/status'

const col = createColumnHelper<AccessLog>()

const STATUS_OPTIONS = [200, 304, 401, 403, 404, 500, 502]
const WAF_OPTIONS: WafAction[] = ['allow', 'deny', 'challenge']

export function AccessLogsPage() {
  const { t } = useI18n()
  const [query, setQuery] = useState('')
  const [host, setHost] = useState('')
  const [status, setStatus] = useState('')
  const [waf, setWaf] = useState('')

  // Unfiltered fetch used only to populate the Host filter dropdown.
  const allHosts = useRpc<Paged<AccessLog>>('access_log.list', { limit: 200 })
  const hostOptions = useMemo(() => {
    const set = new Set((allHosts.data?.items ?? []).map((l) => l.host))
    return Array.from(set).sort()
  }, [allHosts.data])

  const params = useMemo(
    () => ({
      query: query || undefined,
      host: host || undefined,
      status: status ? Number(status) : undefined,
      waf_action: waf || undefined,
      limit: 100,
    }),
    [query, host, status, waf],
  )
  const { data, loading, error, refetch } = useRpc<Paged<AccessLog>>('access_log.search', params, [params])

  const hasFilters = query || host || status || waf
  const clear = () => {
    setQuery('')
    setHost('')
    setStatus('')
    setWaf('')
  }

  const columns = useMemo(
    () => [
      col.accessor('time', { header: t('logs.col.time'), cell: (c) => <span className="whitespace-nowrap text-xs text-slate-500">{formatTime(c.getValue())}</span> }),
      col.accessor('client_ip', { header: t('logs.col.clientIp'), cell: (c) => <span className="font-mono text-xs">{c.getValue()}</span> }),
      col.accessor('method', {
        header: t('logs.col.method'),
        cell: (c) => <span className="font-mono text-xs font-semibold text-slate-600 dark:text-slate-300">{c.getValue()}</span>,
      }),
      col.accessor('host', { header: t('logs.col.host'), cell: (c) => <span className="text-slate-700 dark:text-slate-200">{c.getValue()}</span> }),
      col.accessor('path', { header: t('logs.col.path'), cell: (c) => <span className="max-w-[220px] truncate font-mono text-xs">{c.getValue()}</span> }),
      col.accessor('status', {
        header: t('logs.col.status'),
        cell: (c) => <Badge tone={httpStatusTone(c.getValue())}>{c.getValue()}</Badge>,
      }),
      col.accessor('latency_ms', {
        header: t('logs.col.latency'),
        cell: (c) => {
          const v = c.getValue()
          return <span className={v > 300 ? 'tabular-nums text-amber-600' : 'tabular-nums'}>{v} ms</span>
        },
      }),
      col.accessor('upstream', { header: t('logs.col.upstream'), cell: (c) => <span className="text-xs text-slate-500">{c.getValue()}</span> }),
      col.accessor('waf_action', {
        header: t('logs.col.waf'),
        cell: (c) => <Badge tone={wafActionTone(c.getValue())} dot>{t(`enum.wafAction.${c.getValue()}`)}</Badge>,
      }),
    ],
    [t],
  )

  return (
    <div>
      <PageHeader title={t('logs.title')} description={t('logs.desc')} />

      <Card>
        {/* Filter toolbar */}
        <div className="flex flex-wrap items-center gap-2.5 border-b border-slate-200 px-4 py-3 dark:border-slate-800">
          <div className="relative min-w-[220px] flex-1">
            <Search size={15} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={t('logs.search')}
              className="focus-ring h-9 w-full rounded-md border border-slate-300 bg-white pl-8 pr-3 text-sm placeholder:text-slate-400 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-100"
            />
          </div>
          <Select value={host} onChange={(e) => setHost(e.target.value)} className="w-44">
            <option value="">{t('logs.allHosts')}</option>
            {hostOptions.map((h) => (
              <option key={h} value={h}>{h}</option>
            ))}
          </Select>
          <Select value={status} onChange={(e) => setStatus(e.target.value)} className="w-36">
            <option value="">{t('logs.allStatuses')}</option>
            {STATUS_OPTIONS.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </Select>
          <Select value={waf} onChange={(e) => setWaf(e.target.value)} className="w-36">
            <option value="">{t('logs.allWaf')}</option>
            {WAF_OPTIONS.map((w) => (
              <option key={w} value={w}>{t(`enum.wafAction.${w}`)}</option>
            ))}
          </Select>
          {hasFilters && (
            <Button variant="ghost" size="sm" icon={<X size={14} />} onClick={clear}>{t('common.clear')}</Button>
          )}
          <span className="ml-auto text-xs text-slate-400">{data ? t('logs.matching', { n: data.total }) : '—'}</span>
        </div>

        <StateView loading={loading} error={error} data={data} onRetry={refetch}>
          {(page) => <DataTable columns={columns} data={page.items} searchable={false} emptyMessage={t('logs.empty')} />}
        </StateView>
      </Card>
    </div>
  )
}
