import { useMemo } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { ArrowLeft, Activity, Users, Gauge, AlertTriangle, Clock, Timer, HardDrive, CalendarDays, Clock3 } from 'lucide-react'
import { useRpc } from '@/hooks/useRpc'
import { useI18n } from '@/i18n/I18nContext'
import type { RouteStats } from '@/types'
import { PageHeader } from '@/components/ui/PageHeader'
import { LiveIndicator } from '@/components/ui/LiveIndicator'
import { StatCard } from '@/components/ui/StatCard'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Spinner, ErrorState } from '@/components/ui/States'
import { TrendChart, DonutChart } from '@/components/charts/Charts'
import { formatNumber, formatBytes, deviceIcon, flag, countryLabel } from '@/lib/utils'

const REFRESH_MS = 5000

export function RouteAnalyticsPage() {
  const { t, locale } = useI18n()
  const [params] = useSearchParams()
  const host = params.get('host') ?? ''
  const path = params.get('path') ?? '/'

  const { data, error, refetch } = useRpc<RouteStats>('metrics.route', { host, path }, [host, path], REFRESH_MS)

  const pie = useMemo(
    () => (data?.countries ?? []).map((c) => ({ name: c.country, value: c.requests })),
    [data?.countries],
  )
  const deviceLabel = (d: string) => t(`enum.device.${d}`)
  const devicePie = useMemo(
    () => (data?.devices ?? []).map((d) => ({ name: d.device, value: d.requests })),
    [data?.devices],
  )

  return (
    <div>
      <PageHeader
        title={`${host}${path}`}
        description={t('routes.analyticsPageDesc')}
        actions={
          <div className="flex items-center gap-3">
            <LiveIndicator seconds={REFRESH_MS / 1000} />
            <Link to="/routes" className="inline-flex items-center gap-1.5 rounded-md border border-slate-300 px-3 py-1.5 text-sm text-slate-600 hover:bg-slate-50 dark:border-slate-600 dark:text-slate-300 dark:hover:bg-slate-800">
              <ArrowLeft size={15} /> {t('routes.backToSites')}
            </Link>
          </div>
        }
      />

      {error && !data ? (
        <ErrorState message={error} onRetry={refetch} />
      ) : !data ? (
        <Spinner />
      ) : (
        <div className="space-y-4">
          <p className="text-xs text-slate-500 dark:text-slate-400">{t('routes.analyticsWindow24h')}</p>

          {/* KPI cards */}
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-3 xl:grid-cols-6">
            <StatCard label={t('routes.pv')} value={formatNumber(data.pv)} sub={t('routes.pvSub')} icon={<Activity size={18} />} accent="brand" />
            <StatCard label={t('routes.uv')} value={formatNumber(data.uv)} sub={t('routes.uvSub')} icon={<Users size={18} />} accent="violet" />
            <StatCard label={t('metrics.label.qps')} value={data.current_qps.toFixed(2)} sub="req/s" icon={<Gauge size={18} />} accent="emerald" />
            <StatCard label={t('metrics.label.error_rate')} value={`${data.error_rate}%`} sub={t('routes.last24h')} icon={<AlertTriangle size={18} />} accent="red" />
            <StatCard label={t('metrics.label.latency_p50')} value={`${data.latency_p50}ms`} sub="p50" icon={<Clock size={18} />} accent="amber" />
            <StatCard label={t('metrics.label.latency_p99')} value={`${data.latency_p99}ms`} sub="p99" icon={<Timer size={18} />} accent="amber" />
          </div>

          {/* Site traffic (bytes): total / 30 days / today */}
          {data.traffic ? (
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
              <StatCard label={t('dashboard.trafficTotal')} value={formatBytes(data.traffic.total_bytes)} sub={t('dashboard.trafficTotalSub')} icon={<HardDrive size={18} />} accent="brand" />
              <StatCard label={t('dashboard.traffic30d')} value={formatBytes(data.traffic.bytes_30d)} sub={t('dashboard.traffic30dSub')} icon={<CalendarDays size={18} />} accent="violet" />
              <StatCard label={t('dashboard.trafficToday')} value={formatBytes(data.traffic.bytes_today)} sub={t('dashboard.trafficTodaySub')} icon={<Clock3 size={18} />} accent="emerald" />
            </div>
          ) : null}

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            {/* 24h QPS */}
            <Card>
              <CardHeader title={t('routes.qps24hTitle')} description={t('routes.qps24hDesc')} />
              <CardBody>
                <TrendChart
                  data={data.qps_series}
                  xKey="t"
                  series={[{ key: 'value', label: t('metrics.label.qps'), color: 'brand' }]}
                  yFormatter={(v) => `${v}`}
                  height={260}
                />
              </CardBody>
            </Card>

            {/* Country distribution */}
            <Card>
              <CardHeader title={t('dashboard.countries')} description={t('dashboard.countriesDesc')} />
              <CardBody>
                {pie.length === 0 ? (
                  <p className="py-10 text-center text-sm text-slate-400">{t('dashboard.noGeo')}</p>
                ) : (
                  <DonutChart data={pie} height={260} labelOf={(cc) => `${flag(cc)} ${countryLabel(cc, locale, t('dashboard.unknownCountry'))}`} />
                )}
              </CardBody>
            </Card>

            {/* Device / OS distribution (24h) */}
            <Card>
              <CardHeader title={t('dashboard.devicesTitle')} description={t('dashboard.devicesDesc')} />
              <CardBody>
                {devicePie.length === 0 ? (
                  <p className="py-10 text-center text-sm text-slate-400">{t('dashboard.noDevices')}</p>
                ) : (
                  <DonutChart data={devicePie} height={260} labelOf={(d) => `${deviceIcon(d)} ${deviceLabel(d)}`} />
                )}
              </CardBody>
            </Card>
          </div>
        </div>
      )}
    </div>
  )
}
