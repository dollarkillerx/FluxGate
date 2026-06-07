import {
  Activity,
  ShieldAlert,
  Gauge,
  Network,
  Lock,
  Server,
  ArrowUpRight,
} from 'lucide-react'
import { useRpc } from '@/hooks/useRpc'
import { useI18n } from '@/i18n/I18nContext'
import type { DashboardSummary, DashboardTraffic, SecurityEvent } from '@/types'
import { PageHeader } from '@/components/ui/PageHeader'
import { LiveIndicator } from '@/components/ui/LiveIndicator'
import { StatCard } from '@/components/ui/StatCard'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Spinner, ErrorState } from '@/components/ui/States'
import { TrendChart } from '@/components/charts/Charts'
import { formatFull, formatNumber, timeAgo } from '@/lib/utils'
import { wafActionTone } from '@/lib/status'

const REFRESH_MS = 5000

export function Dashboard() {
  const { t } = useI18n()
  const summary = useRpc<DashboardSummary>('dashboard.summary', {}, [], REFRESH_MS)
  const traffic = useRpc<DashboardTraffic>('dashboard.traffic', {}, [], REFRESH_MS)
  const events = useRpc<SecurityEvent[]>('dashboard.security_events', { limit: 6 }, [], REFRESH_MS)

  return (
    <div>
      <PageHeader
        title={t('dashboard.title')}
        description={t('dashboard.desc')}
        actions={<LiveIndicator seconds={REFRESH_MS / 1000} />}
      />

      {/* KPI cards */}
      {summary.loading && !summary.data ? (
        <Spinner />
      ) : summary.error && !summary.data ? (
        <ErrorState message={summary.error} onRetry={summary.refetch} />
      ) : summary.data ? (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-3 xl:grid-cols-6">
          <StatCard label={t('dashboard.totalRequests')} value={formatNumber(summary.data.total_requests)} sub={formatFull(summary.data.total_requests)} icon={<Activity size={18} />} accent="brand" />
          <StatCard label={t('dashboard.qps')} value={formatFull(summary.data.current_qps)} sub={t('dashboard.qpsSub')} icon={<Gauge size={18} />} accent="violet" />
          <StatCard label={t('dashboard.wafBlocks')} value={formatNumber(summary.data.waf_blocks)} sub={t('dashboard.last24h')} icon={<ShieldAlert size={18} />} accent="red" />
          <StatCard label={t('dashboard.activeConn')} value={formatFull(summary.data.active_connections)} sub={t('dashboard.live')} icon={<Network size={18} />} accent="emerald" />
          <StatCard label={t('dashboard.certs')} value={summary.data.tls_certificates} sub={t('dashboard.managed')} icon={<Lock size={18} />} accent="amber" />
          <StatCard
            label={t('dashboard.backendHealth')}
            value={`${summary.data.healthy_upstreams}/${summary.data.total_upstreams}`}
            sub={t('dashboard.upstreamsHealthy')}
            icon={<Server size={18} />}
            accent={summary.data.healthy_upstreams === summary.data.total_upstreams ? 'emerald' : 'amber'}
          />
        </div>
      ) : null}

      {/* Charts */}
      <div className="mt-5 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title={t('dashboard.requestsChart')} description={t('dashboard.requestsChartDesc')} />
          <CardBody>
            {traffic.data ? (
              <TrendChart
                data={traffic.data.points}
                xKey="t"
                series={[{ key: 'requests', label: t('dashboard.requests'), color: 'brand' }]}
                yFormatter={(v) => formatNumber(v)}
              />
            ) : traffic.error ? (
              <ErrorState message={traffic.error} onRetry={traffic.refetch} />
            ) : (
              <Spinner />
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader title={t('dashboard.wafChart')} description={t('dashboard.wafChartDesc')} />
          <CardBody>
            {traffic.data ? (
              <TrendChart
                data={traffic.data.points}
                xKey="t"
                series={[{ key: 'blocked', label: t('dashboard.blocked'), color: 'red' }]}
                yFormatter={(v) => formatNumber(v)}
              />
            ) : traffic.error ? (
              <ErrorState message={traffic.error} onRetry={traffic.refetch} />
            ) : (
              <Spinner />
            )}
          </CardBody>
        </Card>
      </div>

      {/* Top routes + security events */}
      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title={t('dashboard.topRoutes')} description={t('dashboard.topRoutesDesc')} />
          <CardBody className="p-0">
            {traffic.data ? (
              <div className="divide-y divide-slate-100 dark:divide-slate-800">
                {traffic.data.top_routes.map((r) => {
                  const max = traffic.data!.top_routes[0].requests
                  return (
                    <div key={r.route} className="px-5 py-3">
                      <div className="flex items-center justify-between text-sm">
                        <span className="flex items-center gap-1.5 font-medium text-slate-700 dark:text-slate-200">
                          <ArrowUpRight size={14} className="text-brand-500" />
                          {r.route}
                        </span>
                        <span className="tabular-nums text-slate-500 dark:text-slate-400">{formatNumber(r.requests)}</span>
                      </div>
                      <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                        <div className="h-full rounded-full bg-brand-500" style={{ width: `${(r.requests / max) * 100}%` }} />
                      </div>
                      <div className="mt-1 text-xs text-red-500">{t('dashboard.blockedN', { n: formatNumber(r.blocked) })}</div>
                    </div>
                  )
                })}
              </div>
            ) : (
              <Spinner />
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader title={t('dashboard.recentEvents')} description={t('dashboard.recentEventsDesc')} />
          <CardBody className="p-0">
            {events.data ? (
              <div className="divide-y divide-slate-100 dark:divide-slate-800">
                {events.data.map((e) => (
                  <div key={e.id} className="flex items-center justify-between gap-3 px-5 py-3">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <Badge tone={wafActionTone(e.action)} dot>
                          {t(`enum.wafAction.${e.action}`)}
                        </Badge>
                        <span className="truncate text-sm font-medium text-slate-700 dark:text-slate-200">{e.rule}</span>
                      </div>
                      <p className="mt-1 truncate font-mono text-xs text-slate-500 dark:text-slate-400">
                        {e.client_ip} → {e.path}
                      </p>
                    </div>
                    <span className="shrink-0 text-xs text-slate-400">{timeAgo(e.time)}</span>
                  </div>
                ))}
              </div>
            ) : (
              <Spinner />
            )}
          </CardBody>
        </Card>
      </div>
    </div>
  )
}
