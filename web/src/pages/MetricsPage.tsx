import { useMemo } from 'react'
import { Cpu, MemoryStick, ArrowDownToLine, ArrowUpFromLine } from 'lucide-react'
import { useRpc } from '@/hooks/useRpc'
import { useI18n } from '@/i18n/I18nContext'
import type { MetricSeries } from '@/types'
import { PageHeader } from '@/components/ui/PageHeader'
import { LiveIndicator } from '@/components/ui/LiveIndicator'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Spinner, ErrorState } from '@/components/ui/States'
import { TrendChart, Sparkline } from '@/components/charts/Charts'
import { upstreamTone } from '@/lib/status'

/** Merge several MetricSeries (sharing the same x-axis) into chart rows. */
function mergeSeries(list: MetricSeries[], keys: string[]) {
  const picked = list.filter((s) => keys.includes(s.key))
  const len = picked[0]?.series.length ?? 0
  return Array.from({ length: len }, (_, i) => {
    const row: Record<string, any> = { t: picked[0]?.series[i]?.t ?? '' }
    for (const s of picked) row[s.key] = s.series[i]?.value ?? 0
    return row
  })
}

const ICONS: Record<string, JSX.Element> = {
  cpu: <Cpu size={16} />,
  memory: <MemoryStick size={16} />,
  net_in: <ArrowDownToLine size={16} />,
  net_out: <ArrowUpFromLine size={16} />,
}
const COLORS = ['brand', 'violet', 'emerald', 'amber'] as const

/** Translate a metric label by its key, falling back to the server-sent label. */
function useMetricLabel() {
  const { t } = useI18n()
  return (m: MetricSeries) => {
    const key = `metrics.label.${m.key}`
    const translated = t(key)
    return translated === key ? m.label : translated
  }
}

function MetricCard({ m, color, icon }: { m: MetricSeries; color: (typeof COLORS)[number]; icon?: JSX.Element }) {
  const label = useMetricLabel()
  return (
    <Card className="overflow-hidden">
      <div className="px-4 pt-4">
        <div className="flex items-center justify-between">
          <span className="flex items-center gap-1.5 text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">
            {icon}
            {label(m)}
          </span>
        </div>
        <div className="mt-1.5 text-2xl font-semibold tabular-nums text-slate-900 dark:text-white">
          {m.current.toLocaleString('en-US', { maximumFractionDigits: 2 })}
          <span className="ml-1 text-sm font-normal text-slate-400">{m.unit}</span>
        </div>
      </div>
      <Sparkline data={m.series} color={color} />
    </Card>
  )
}

const REFRESH_MS = 3000

export function MetricsPage() {
  const { t } = useI18n()
  const system = useRpc<MetricSeries[]>('metrics.system', {}, [], REFRESH_MS)
  const traffic = useRpc<MetricSeries[]>('metrics.traffic', {}, [], REFRESH_MS)
  const upstream = useRpc<MetricSeries[]>('metrics.upstream', {}, [], REFRESH_MS)
  const waf = useRpc<MetricSeries[]>('metrics.waf', {}, [], REFRESH_MS)

  const latencyData = useMemo(() => (traffic.data ? mergeSeries(traffic.data, ['latency_p50', 'latency_p99']) : []), [traffic.data])
  const wafData = useMemo(() => (waf.data ? mergeSeries(waf.data, ['blocks', 'challenges']) : []), [waf.data])

  return (
    <div>
      <PageHeader
        title={t('metrics.title')}
        description={t('metrics.desc')}
        actions={<LiveIndicator seconds={REFRESH_MS / 1000} />}
      />

      {/* System resource cards */}
      <section>
        <h2 className="mb-3 text-sm font-semibold text-slate-700 dark:text-slate-200">{t('metrics.system')}</h2>
        {system.error ? (
          <ErrorState message={system.error} onRetry={system.refetch} />
        ) : system.data ? (
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            {system.data.map((m, i) => (
              <MetricCard key={m.key} m={m} color={COLORS[i % COLORS.length]} icon={ICONS[m.key]} />
            ))}
          </div>
        ) : (
          <Spinner />
        )}
      </section>

      {/* Traffic cards */}
      <section className="mt-6">
        <h2 className="mb-3 text-sm font-semibold text-slate-700 dark:text-slate-200">{t('metrics.traffic')}</h2>
        {traffic.data ? (
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            {traffic.data.map((m, i) => (
              <MetricCard key={m.key} m={m} color={COLORS[i % COLORS.length]} />
            ))}
          </div>
        ) : (
          <Spinner />
        )}
      </section>

      {/* Charts */}
      <div className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title={t('metrics.latencyTitle')} description={t('metrics.latencyDesc')} />
          <CardBody>
            {latencyData.length ? (
              <TrendChart
                data={latencyData}
                xKey="t"
                area={false}
                series={[
                  { key: 'latency_p50', label: 'p50', color: 'brand' },
                  { key: 'latency_p99', label: 'p99', color: 'red' },
                ]}
                yFormatter={(v) => `${v}ms`}
              />
            ) : (
              <Spinner />
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader title={t('metrics.wafTitle')} description={t('metrics.wafDesc')} />
          <CardBody>
            {wafData.length ? (
              <TrendChart
                data={wafData}
                xKey="t"
                series={[
                  { key: 'blocks', label: t('metrics.label.blocks'), color: 'red' },
                  { key: 'challenges', label: t('metrics.label.challenges'), color: 'amber' },
                ]}
              />
            ) : (
              <Spinner />
            )}
          </CardBody>
        </Card>
      </div>

      {/* Upstream health */}
      <section className="mt-6">
        <h2 className="mb-3 text-sm font-semibold text-slate-700 dark:text-slate-200">{t('metrics.upstreamHealth')}</h2>
        {upstream.data ? (
          <div className="grid grid-cols-2 gap-4 md:grid-cols-3 lg:grid-cols-6">
            {upstream.data.map((m) => {
              const pct = Math.round(m.current)
              const statusKey = pct === 100 ? 'healthy' : pct === 0 ? 'down' : 'degraded'
              return (
                <Card key={m.key} className="p-4">
                  <div className="flex items-center justify-between">
                    <span className="truncate text-xs font-medium text-slate-600 dark:text-slate-300">{m.label}</span>
                  </div>
                  <div className="mt-2 text-xl font-semibold tabular-nums text-slate-900 dark:text-white">{pct}%</div>
                  <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                    <div className={`h-full rounded-full ${pct === 100 ? 'bg-emerald-500' : pct === 0 ? 'bg-red-500' : 'bg-amber-500'}`} style={{ width: `${pct}%` }} />
                  </div>
                  <div className="mt-2">
                    <Badge tone={upstreamTone(statusKey)} dot>{t(`enum.upstreamStatus.${statusKey}`)}</Badge>
                  </div>
                </Card>
              )
            })}
          </div>
        ) : (
          <Spinner />
        )}
      </section>
    </div>
  )
}
