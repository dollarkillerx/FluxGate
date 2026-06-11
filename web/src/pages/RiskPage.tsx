import { useMemo, useState } from 'react'
import { ShieldAlert, Bug, Globe2, Activity, ShieldCheck } from 'lucide-react'
import { useRpc } from '@/hooks/useRpc'
import { rpc } from '@/api/rpc'
import { useToast } from '@/context/ToastContext'
import { useI18n } from '@/i18n/I18nContext'
import type { AttackOverview, SecurityEvent } from '@/types'
import { Button } from '@/components/ui/Button'
import { PageHeader } from '@/components/ui/PageHeader'
import { LiveIndicator } from '@/components/ui/LiveIndicator'
import { StatCard } from '@/components/ui/StatCard'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Spinner, ErrorState } from '@/components/ui/States'
import { TrendChart, DonutChart } from '@/components/charts/Charts'
import { formatNumber, flag, timeAgo } from '@/lib/utils'
import { wafActionTone } from '@/lib/status'

const REFRESH_MS = 5000

export function RiskPage() {
  const { t, locale } = useI18n()
  const toast = useToast()
  const attacks = useRpc<AttackOverview>('dashboard.attacks', {}, [], REFRESH_MS)
  const events = useRpc<SecurityEvent[]>('dashboard.security_events', { limit: 30 }, [], REFRESH_MS)

  // Per-event "accept false positive" state: 'pending' while the request is in
  // flight, 'done' once an exception has been created for that event.
  const [fpState, setFpState] = useState<Record<string, 'pending' | 'done'>>({})

  const acceptFp = async (e: SecurityEvent) => {
    if (!e.module || fpState[e.id]) return
    setFpState((s) => ({ ...s, [e.id]: 'pending' }))
    try {
      await rpc.call('waf.exception.create', {
        module: e.module,
        path_prefix: e.path,
        param: e.param || undefined,
        note: `accepted FP from risk event (${e.rule})`,
      })
      setFpState((s) => ({ ...s, [e.id]: 'done' }))
      toast.success('Exception added', `${e.module} on ${e.path}${e.param ? ` [${e.param}]` : ''} is now allowed`)
    } catch (err: any) {
      setFpState((s) => {
        const n = { ...s }
        delete n[e.id]
        return n
      })
      toast.error('Could not add exception', err?.message)
    }
  }

  const regionNames = useMemo(() => {
    try {
      return new Intl.DisplayNames([locale], { type: 'region' })
    } catch {
      return null
    }
  }, [locale])
  const countryName = (cc: string) =>
    cc === '??' || !/^[A-Za-z]{2}$/.test(cc) ? t('dashboard.unknownCountry') : (regionNames?.of(cc.toUpperCase()) ?? cc)

  const countryPie = useMemo(
    () => (attacks.data?.top_countries ?? []).map((c) => ({ name: c.country, value: c.requests })),
    [attacks.data?.top_countries],
  )

  const d = attacks.data

  return (
    <div>
      <PageHeader
        title={t('risk.title')}
        description={t('risk.desc')}
        actions={<LiveIndicator seconds={REFRESH_MS / 1000} />}
      />

      {attacks.error && !d ? (
        <ErrorState message={attacks.error} onRetry={attacks.refetch} />
      ) : !d ? (
        <Spinner />
      ) : (
        <div className="space-y-4">
          {/* KPIs */}
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <StatCard label={t('risk.total24h')} value={formatNumber(d.total)} sub={t('risk.last24h')} icon={<ShieldAlert size={18} />} accent="red" />
            <StatCard label={t('risk.distinctUas')} value={formatNumber(d.top_uas.length)} sub={t('risk.top')} icon={<Bug size={18} />} accent="amber" />
            <StatCard label={t('risk.countries')} value={formatNumber(d.top_countries.length)} sub={t('risk.sources')} icon={<Globe2 size={18} />} accent="violet" />
            <StatCard label={t('risk.peakHour')} value={formatNumber(Math.max(0, ...d.timeline.map((p) => p.blocked)))} sub={t('risk.perHour')} icon={<Activity size={18} />} accent="brand" />
          </div>

          {/* Blocks over 24h */}
          <Card>
            <CardHeader title={t('risk.blocks24h')} description={t('risk.blocks24hDesc')} />
            <CardBody>
              <TrendChart
                data={d.timeline}
                xKey="t"
                series={[{ key: 'blocked', label: t('dashboard.blocked'), color: 'red' }]}
                yFormatter={(v) => formatNumber(v)}
                height={240}
              />
            </CardBody>
          </Card>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            {/* Top malicious User-Agents */}
            <Card>
              <CardHeader title={t('risk.topUas')} description={t('risk.topUasDesc')} />
              <CardBody className="p-0">
                {d.top_uas.length === 0 ? (
                  <p className="py-10 text-center text-sm text-slate-400">{t('risk.noData')}</p>
                ) : (
                  <div className="divide-y divide-slate-100 dark:divide-slate-800">
                    {d.top_uas.map((u, i) => {
                      const max = d.top_uas[0].count || 1
                      const label = u.ua === '(none)' ? t('risk.uaNone') : u.ua
                      return (
                        <div key={u.ua} className="px-5 py-2.5">
                          <div className="flex items-center justify-between gap-3 text-sm">
                            <span className="flex min-w-0 items-center gap-2">
                              <span className="w-4 shrink-0 text-right tabular-nums text-xs text-slate-400">{i + 1}</span>
                              <span className="truncate font-mono text-xs text-slate-700 dark:text-slate-200" title={label}>{label}</span>
                            </span>
                            <span className="shrink-0 tabular-nums text-slate-500 dark:text-slate-400">{formatNumber(u.count)}</span>
                          </div>
                          <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                            <div className="h-full rounded-full bg-amber-500" style={{ width: `${(u.count / max) * 100}%` }} />
                          </div>
                        </div>
                      )
                    })}
                  </div>
                )}
              </CardBody>
            </Card>

            {/* Attack origins (countries) */}
            <Card>
              <CardHeader title={t('risk.attackOrigins')} description={t('risk.attackOriginsDesc')} />
              <CardBody>
                {countryPie.length === 0 ? (
                  <p className="py-10 text-center text-sm text-slate-400">{t('risk.noGeo')}</p>
                ) : (
                  <div className="grid grid-cols-1 items-center gap-6 sm:grid-cols-2">
                    <DonutChart data={countryPie} height={240} labelOf={(cc) => `${flag(cc)} ${countryName(cc)}`} />
                    <div className="space-y-2.5">
                      {(d.top_countries ?? []).slice(0, 8).map((c) => {
                        const max = d.top_countries[0].requests || 1
                        return (
                          <div key={c.country}>
                            <div className="flex items-center justify-between text-sm">
                              <span className="flex min-w-0 items-center gap-2">
                                <span className="text-base leading-none">{flag(c.country)}</span>
                                <span className="truncate text-slate-700 dark:text-slate-200">{countryName(c.country)}</span>
                              </span>
                              <span className="shrink-0 tabular-nums text-slate-500 dark:text-slate-400">{formatNumber(c.requests)}</span>
                            </div>
                            <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                              <div className="h-full rounded-full bg-red-500" style={{ width: `${(c.requests / max) * 100}%` }} />
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}
              </CardBody>
            </Card>
          </div>

          {/* Recent attack events */}
          <Card>
            <CardHeader title={t('risk.recentEvents')} description={t('risk.recentEventsDesc')} />
            <CardBody className="p-0">
              {!events.data ? (
                <Spinner />
              ) : events.data.length === 0 ? (
                <p className="py-10 text-center text-sm text-slate-400">{t('risk.noData')}</p>
              ) : (
                <div className="divide-y divide-slate-100 dark:divide-slate-800">
                  {events.data.map((e) => (
                    <div key={e.id} className="px-5 py-3">
                      <div className="flex items-center justify-between gap-3">
                        <div className="flex min-w-0 items-center gap-2">
                          <Badge tone={wafActionTone(e.action)} dot>{t(`enum.wafAction.${e.action}`)}</Badge>
                          {e.module ? <Badge tone="neutral">{e.module}</Badge> : null}
                          {e.risk ? (
                            <Badge tone={e.risk === 'high' ? 'danger' : e.risk === 'medium' ? 'warning' : 'neutral'}>{e.risk}</Badge>
                          ) : null}
                          {e.enforced === false && e.module ? (
                            <Badge tone="warning">not enforced</Badge>
                          ) : null}
                          <span className="truncate text-sm font-medium text-slate-700 dark:text-slate-200">{e.rule}</span>
                        </div>
                        <div className="flex shrink-0 items-center gap-2">
                          {/* One-click accept-false-positive: only for semantic
                              detections (regex-rule events have no exception to scope). */}
                          {e.module ? (
                            <Button
                              variant="ghost"
                              size="sm"
                              icon={<ShieldCheck size={13} className="text-emerald-500" />}
                              loading={fpState[e.id] === 'pending'}
                              disabled={fpState[e.id] === 'done'}
                              onClick={() => acceptFp(e)}
                              title={`Accept as false positive — allow ${e.module} on ${e.path}${e.param ? ` [${e.param}]` : ''}`}
                            >
                              {fpState[e.id] === 'done' ? 'Accepted' : 'Accept FP'}
                            </Button>
                          ) : null}
                          <span className="text-xs text-slate-400">{timeAgo(e.time)}</span>
                        </div>
                      </div>
                      <p className="mt-1 truncate font-mono text-xs text-slate-500 dark:text-slate-400">{e.client_ip} → {e.path}</p>
                      {e.snippet ? (
                        <p className="mt-0.5 truncate font-mono text-[11px] text-slate-400" title={e.snippet}>
                          {e.location}{e.param ? `[${e.param}]` : ''}: {e.snippet}
                        </p>
                      ) : null}
                      {e.decision_trace ? (
                        <p className="mt-0.5 truncate text-[11px] text-slate-400" title={e.decision_trace}>
                          <span className="text-slate-500 dark:text-slate-500">why:</span> {e.decision_trace}
                        </p>
                      ) : null}
                      {e.user_agent ? (
                        <p className="mt-0.5 truncate font-mono text-[11px] text-slate-400" title={e.user_agent}>UA: {e.user_agent}</p>
                      ) : null}
                    </div>
                  ))}
                </div>
              )}
            </CardBody>
          </Card>
        </div>
      )}
    </div>
  )
}
