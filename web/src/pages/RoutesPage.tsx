import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Plus, Pencil, Trash2, Activity, Globe, ShieldCheck, Lock, ChevronRight } from 'lucide-react'
import { useRpc } from '@/hooks/useRpc'
import { rpc } from '@/api/rpc'
import { useToast } from '@/context/ToastContext'
import { useI18n } from '@/i18n/I18nContext'
import type { RedirectRule, Route, Site, Upstream, TlsCertificate } from '@/types'
import { PageHeader } from '@/components/ui/PageHeader'
import { Card, CardBody } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Toggle } from '@/components/ui/Toggle'
import { Modal } from '@/components/ui/Modal'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { Field, Input, Select } from '@/components/ui/Field'
import { CountryMultiSelect } from '@/components/ui/CountryMultiSelect'
import { StateView } from '@/components/ui/States'

// ---------------------------------------------------------------------------
// Site form
// ---------------------------------------------------------------------------

interface SiteForm {
  id?: string
  name: string
  host: string
  tls_enabled: boolean
  cert_id: string
  https_redirect: boolean
  waf_enabled: boolean
  max_body_mb: number
  upstream_timeout_secs: number
  block_crawler_ua: boolean
  browser_only: boolean
  rewrite_robots: boolean
  redirects: RedirectRule[]
  blocked_countries: string[]
  block_datacenter: boolean
  cloudflare_only: boolean
  enabled: boolean
}
const emptySite: SiteForm = { name: '', host: '', tls_enabled: true, cert_id: '', https_redirect: true, waf_enabled: true, max_body_mb: 500, upstream_timeout_secs: 120, block_crawler_ua: false, browser_only: false, rewrite_robots: false, redirects: [], blocked_countries: [], block_datacenter: false, cloudflare_only: false, enabled: true }

/** A certificate covers `host` if its domain matches exactly (case-insensitive)
 *  or via a single-label wildcard (`*.example.com` ⊇ `a.example.com`). */
function certMatchesHost(certDomain: string, host: string): boolean {
  if (!host) return false
  const c = certDomain.toLowerCase()
  const h = host.toLowerCase()
  if (c === h) return true
  if (c.startsWith('*.')) {
    return h.endsWith(c.slice(1)) && h.split('.').length === c.split('.').length
  }
  return false
}

interface RouteForm {
  id?: string
  site_id: string
  path: string
  upstream: string
  waf_enabled: boolean
  enabled: boolean
}

export function RoutesPage() {
  const toast = useToast()
  const { t } = useI18n()
  const navigate = useNavigate()
  const openAnalytics = (host: string, path: string) =>
    navigate(`/routes/analytics?host=${encodeURIComponent(host)}&path=${encodeURIComponent(path)}`)
  const sites = useRpc<Site[]>('site.list')
  const routes = useRpc<Route[]>('route.list')
  const upstreams = useRpc<Upstream[]>('upstream.list')
  const certs = useRpc<TlsCertificate[]>('tls.cert.list')

  const [siteForm, setSiteForm] = useState<SiteForm | null>(null)
  const [routeForm, setRouteForm] = useState<RouteForm | null>(null)
  const [saving, setSaving] = useState(false)
  const [siteToDelete, setSiteToDelete] = useState<Site | null>(null)
  const [routeToDelete, setRouteToDelete] = useState<Route | null>(null)
  const [expanded, setExpanded] = useState<Record<string, boolean>>({})
  const [advanced, setAdvanced] = useState(false)
  const toggleExpand = (id: string) => setExpanded((e) => ({ ...e, [id]: !e[id] }))

  const routesBySite = useMemo(() => {
    const map: Record<string, Route[]> = {}
    for (const r of routes.data ?? []) (map[r.site_id] ??= []).push(r)
    return map
  }, [routes.data])

  // Certificate options for the site form: if any cert matches the host, show
  // only those (e.g. hide `localhost` when a cert for the real domain exists).
  // The currently-selected cert is always kept so editing never loses it.
  const host = siteForm?.host ?? ''
  const certOptions = useMemo(() => {
    const all = certs.data ?? []
    const matching = all.filter((c) => certMatchesHost(c.domain, host))
    let opts = matching.length > 0 ? matching : all
    if (siteForm?.cert_id && !opts.some((c) => c.id === siteForm.cert_id)) {
      const sel = all.find((c) => c.id === siteForm.cert_id)
      if (sel) opts = [...opts, sel]
    }
    return opts
  }, [certs.data, host, siteForm?.cert_id])

  // Auto-select the matching cert when none is chosen yet (new-site flow).
  useEffect(() => {
    if (!siteForm || !siteForm.tls_enabled || siteForm.cert_id) return
    const match = (certs.data ?? []).find((c) => certMatchesHost(c.domain, siteForm.host))
    if (match) setSiteForm((f) => (f ? { ...f, cert_id: match.id } : f))
  }, [siteForm, certs.data])

  const reload = () => {
    sites.refetch()
    routes.refetch()
  }

  // --- site CRUD ---
  const saveSite = async () => {
    if (!siteForm) return
    if (!siteForm.host.trim()) return toast.warning(t('common.required', { field: t('sites.field.host') }))
    if (siteForm.tls_enabled && !siteForm.cert_id) return toast.warning(t('routes.selectCertRequired'))
    setSaving(true)
    try {
      await rpc.call(siteForm.id ? 'site.update' : 'site.create', siteForm)
      toast.success(siteForm.id ? t('sites.updated') : t('sites.created'), siteForm.host)
      setSiteForm(null)
      reload()
    } catch (e: any) {
      toast.error(t('toast.saveFailed'), e?.message)
    } finally {
      setSaving(false)
    }
  }
  const deleteSite = async () => {
    if (!siteToDelete) return
    try {
      await rpc.call('site.delete', { id: siteToDelete.id })
      toast.success(t('sites.deleted'), siteToDelete.host)
      reload()
    } catch (e: any) {
      toast.error(t('toast.deleteFailed'), e?.message)
    }
  }
  const toggleSite = async (s: Site, enabled: boolean) => {
    try {
      await rpc.call('site.update', { id: s.id, enabled })
      reload()
    } catch (e: any) {
      toast.error(t('toast.updateFailed'), e?.message)
    }
  }

  // --- route (path) CRUD ---
  const saveRoute = async () => {
    if (!routeForm) return
    if (!routeForm.upstream) return toast.warning(t('common.required', { field: t('routes.field.upstream') }))
    setSaving(true)
    try {
      await rpc.call(routeForm.id ? 'route.update' : 'route.create', routeForm)
      toast.success(routeForm.id ? t('routes.updated') : t('routes.created'), routeForm.path)
      setRouteForm(null)
      routes.refetch()
    } catch (e: any) {
      toast.error(t('toast.saveFailed'), e?.message)
    } finally {
      setSaving(false)
    }
  }
  const deleteRoute = async () => {
    if (!routeToDelete) return
    try {
      await rpc.call('route.delete', { id: routeToDelete.id })
      toast.success(t('routes.deleted'), routeToDelete.path)
      routes.refetch()
    } catch (e: any) {
      toast.error(t('toast.deleteFailed'), e?.message)
    }
  }
  const toggleRoute = async (r: Route, enabled: boolean) => {
    try {
      await rpc.call(enabled ? 'route.enable' : 'route.disable', { id: r.id })
      routes.refetch()
    } catch (e: any) {
      toast.error(t('toast.updateFailed'), e?.message)
    }
  }

  const certLabel = (id?: string | null) => {
    const c = certs.data?.find((x) => x.id === id)
    return c ? c.domain : '—'
  }

  return (
    <div>
      <PageHeader
        title={t('sites.title')}
        description={t('sites.desc')}
        actions={<Button icon={<Plus size={16} />} onClick={() => { setAdvanced(false); setSiteForm({ ...emptySite }) }}>{t('sites.new')}</Button>}
      />

      <StateView loading={sites.loading} error={sites.error} data={sites.data} onRetry={reload}>
        {(siteList) =>
          siteList.length === 0 ? (
            <Card><CardBody><p className="py-8 text-center text-sm text-slate-400">{t('sites.empty')}</p></CardBody></Card>
          ) : (
            <div className="space-y-4">
              {siteList.map((site) => {
                const paths = routesBySite[site.id] ?? []
                const isOpen = expanded[site.id] ?? false
                return (
                  <Card key={site.id} className={site.enabled ? '' : 'opacity-60'}>
                    {/* Site header */}
                    <div className={`flex flex-wrap items-start justify-between gap-3 px-4 py-3 ${isOpen ? 'border-b border-slate-200 dark:border-slate-800' : ''}`}>
                      <button type="button" onClick={() => toggleExpand(site.id)} className="group min-w-0 flex-1 text-left" aria-expanded={isOpen} aria-label={t('sites.togglePaths')}>
                        <div className="flex items-center gap-2">
                          <ChevronRight size={16} className={`shrink-0 text-slate-400 transition-transform ${isOpen ? 'rotate-90' : ''}`} />
                          <Globe size={16} className="shrink-0 text-slate-400" />
                          <span className="truncate font-semibold text-slate-800 group-hover:text-brand-600 dark:text-slate-100">{site.host}</span>
                          {site.name && site.name !== site.host && <span className="truncate text-xs text-slate-400">{site.name}</span>}
                          <span className="shrink-0 rounded-full bg-slate-100 px-2 py-0.5 text-[11px] tabular-nums text-slate-500 dark:bg-slate-700/50 dark:text-slate-300">{t('sites.pathCount', { n: paths.length })}</span>
                        </div>
                        <div className="mt-1.5 flex flex-wrap items-center gap-1.5 pl-6">
                          {site.tls_enabled ? (
                            <Badge tone="success" dot><Lock size={10} className="mr-0.5 inline" />TLS · {certLabel(site.cert_id)}</Badge>
                          ) : (
                            <Badge tone="neutral">{t('routes.enableTls')}: {t('common.off')}</Badge>
                          )}
                          {site.tls_enabled && site.https_redirect && <Badge tone="info">HTTP→HTTPS</Badge>}
                          {(site.redirects?.length ?? 0) > 0 && <Badge tone="info">{t('sites.redirectBadge', { n: site.redirects!.length })}</Badge>}
                          {site.waf_enabled && <Badge tone="warning"><ShieldCheck size={10} className="mr-0.5 inline" />WAF</Badge>}
                        </div>
                      </button>
                      <div className="flex items-center gap-1">
                        <Toggle checked={site.enabled} onChange={(v) => toggleSite(site, v)} aria-label="Toggle site" />
                        <Button variant="ghost" size="sm" icon={<Plus size={14} />} onClick={() => { setExpanded((e) => ({ ...e, [site.id]: true })); setRouteForm({ site_id: site.id, path: '/', upstream: upstreams.data?.[0]?.name ?? '', waf_enabled: site.waf_enabled, enabled: true }) }}>
                          {t('sites.addPath')}
                        </Button>
                        <Button variant="ghost" size="sm" icon={<Pencil size={14} />} onClick={() => { setAdvanced(false); setSiteForm({ id: site.id, name: site.name, host: site.host, tls_enabled: site.tls_enabled, cert_id: site.cert_id ?? '', https_redirect: site.https_redirect ?? false, waf_enabled: site.waf_enabled, max_body_mb: site.max_body_mb ?? 500, upstream_timeout_secs: site.upstream_timeout_secs ?? 120, block_crawler_ua: site.block_crawler_ua ?? false, browser_only: site.browser_only ?? false, rewrite_robots: site.rewrite_robots ?? false, redirects: site.redirects ?? [], blocked_countries: site.blocked_countries ?? [], block_datacenter: site.block_datacenter ?? false, cloudflare_only: site.cloudflare_only ?? false, enabled: site.enabled }) }} aria-label={t('common.edit')} />
                        <Button variant="ghost" size="sm" icon={<Trash2 size={14} className="text-red-500" />} onClick={() => setSiteToDelete(site)} aria-label={t('common.delete')} />
                      </div>
                    </div>

                    {/* Paths table (collapsible) */}
                    {!isOpen ? null : paths.length === 0 ? (
                      <p className="px-4 py-5 text-center text-xs text-slate-400">{t('sites.noPaths')}</p>
                    ) : (
                      <table className="w-full text-sm">
                        <thead>
                          <tr className="border-b border-slate-100 text-left text-[11px] uppercase tracking-wide text-slate-400 dark:border-slate-800">
                            <th className="px-4 py-2 font-medium">{t('routes.col.path')}</th>
                            <th className="px-4 py-2 font-medium">{t('routes.col.upstream')}</th>
                            <th className="px-4 py-2 font-medium">{t('routes.col.waf')}</th>
                            <th className="px-4 py-2 font-medium">{t('routes.col.enabled')}</th>
                            <th className="px-4 py-2" />
                          </tr>
                        </thead>
                        <tbody>
                          {paths.map((r) => (
                            <tr key={r.id} className="border-b border-slate-50 last:border-0 dark:border-slate-800/50">
                              <td className="px-4 py-2.5">
                                <button type="button" onClick={() => openAnalytics(site.host, r.path)} className="font-mono text-xs text-slate-700 hover:text-brand-600 dark:text-slate-200" title={t('routes.analyze')}>
                                  {r.path}
                                </button>
                                {r.name && <span className="ml-2 text-xs text-slate-400">{r.name}</span>}
                              </td>
                              <td className="px-4 py-2.5"><Badge tone="info">{r.upstream}</Badge></td>
                              <td className="px-4 py-2.5">{r.waf_enabled ? <Badge tone="success" dot>{t('common.on')}</Badge> : <Badge tone="neutral">{t('common.off')}</Badge>}</td>
                              <td className="px-4 py-2.5"><Toggle checked={r.enabled} onChange={(v) => toggleRoute(r, v)} aria-label="Toggle path" /></td>
                              <td className="px-4 py-2.5">
                                <div className="flex justify-end gap-1">
                                  <Button variant="ghost" size="sm" icon={<Activity size={14} />} onClick={() => openAnalytics(site.host, r.path)} aria-label={t('routes.analyze')} />
                                  <Button variant="ghost" size="sm" icon={<Pencil size={14} />} onClick={() => setRouteForm({ id: r.id, site_id: r.site_id, path: r.path, upstream: r.upstream, waf_enabled: r.waf_enabled, enabled: r.enabled })} aria-label={t('common.edit')} />
                                  <Button variant="ghost" size="sm" icon={<Trash2 size={14} className="text-red-500" />} onClick={() => setRouteToDelete(r)} aria-label={t('common.delete')} />
                                </div>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </Card>
                )
              })}
            </div>
          )
        }
      </StateView>

      {/* Site create / edit modal */}
      <Modal
        size="xl"
        open={!!siteForm}
        onClose={() => setSiteForm(null)}
        title={siteForm?.id ? t('sites.editTitle') : t('sites.newTitle')}
        footer={
          <>
            <Button variant="secondary" onClick={() => setSiteForm(null)}>{t('common.cancel')}</Button>
            <Button onClick={saveSite} loading={saving}>{siteForm?.id ? t('common.saveChanges') : t('sites.createBtn')}</Button>
          </>
        }
      >
        {siteForm && (
          <div className="space-y-4">
            <Field label={t('sites.field.host')}>
              <Input value={siteForm.host} onChange={(e) => setSiteForm({ ...siteForm, host: e.target.value })} placeholder="www.example.com" />
            </Field>
            <Field label={t('sites.field.name')}>
              <Input value={siteForm.name} onChange={(e) => setSiteForm({ ...siteForm, name: e.target.value })} placeholder={siteForm.host || 'Marketing Site'} />
            </Field>
            <div className="flex flex-wrap gap-6 pt-1">
              <label className="flex items-center gap-2.5 text-sm text-slate-700 dark:text-slate-200">
                <Toggle checked={siteForm.tls_enabled} onChange={(v) => setSiteForm({ ...siteForm, tls_enabled: v })} aria-label="TLS" /> {t('routes.enableTls')}
              </label>
              <label className="flex items-center gap-2.5 text-sm text-slate-700 dark:text-slate-200">
                <Toggle checked={siteForm.waf_enabled} onChange={(v) => setSiteForm({ ...siteForm, waf_enabled: v })} aria-label="WAF" /> {t('sites.wafDefault')}
              </label>
              <label className="flex items-center gap-2.5 text-sm text-slate-700 dark:text-slate-200">
                <Toggle checked={siteForm.enabled} onChange={(v) => setSiteForm({ ...siteForm, enabled: v })} aria-label="Enabled" /> {t('common.active')}
              </label>
            </div>
            {siteForm.tls_enabled && (
              <>
                <Field label={t('routes.field.cert')} hint={certs.data && certs.data.length === 0 ? t('routes.noCerts') : t('routes.certHint')}>
                  <Select value={siteForm.cert_id} onChange={(e) => setSiteForm({ ...siteForm, cert_id: e.target.value })}>
                    <option value="" disabled>{t('routes.selectCert')}</option>
                    {certOptions.map((c) => (
                      <option key={c.id} value={c.id}>{c.domain} · {t(`enum.certStatus.${c.status}`)}</option>
                    ))}
                  </Select>
                </Field>
                <label className="flex items-center gap-2.5 text-sm text-slate-700 dark:text-slate-200">
                  <Toggle checked={siteForm.https_redirect} onChange={(v) => setSiteForm({ ...siteForm, https_redirect: v })} aria-label="HTTPS redirect" />
                  <span>{t('routes.httpsRedirect')}<span className="ml-1 text-xs text-slate-400">{t('routes.httpsRedirectHint')}</span></span>
                </label>
              </>
            )}

            {/* Redirect rules (301 / 302) */}
            <div className="border-t border-slate-200 pt-3 dark:border-slate-700">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="text-sm font-medium text-slate-700 dark:text-slate-200">{t('sites.redirects')}</p>
                  <p className="mt-0.5 text-xs text-slate-400">{t('sites.redirectsHint')}</p>
                </div>
                <Button variant="secondary" size="sm" className="shrink-0 whitespace-nowrap" icon={<Plus size={14} />} onClick={() => setSiteForm({ ...siteForm, redirects: [...siteForm.redirects, { path: '', target: '', status: 301 }] })}>
                  {t('sites.addRedirect')}
                </Button>
              </div>
              {siteForm.redirects.length > 0 && (
                <div className="mt-3 space-y-2">
                  <div className="flex items-center gap-2 px-0.5 text-[11px] uppercase tracking-wide text-slate-400">
                    <span className="min-w-0 flex-1">{t('sites.redirectFrom')}</span>
                    <span className="w-3.5 shrink-0" />
                    <span className="min-w-0 flex-1">{t('sites.redirectTo')}</span>
                    <span className="w-[4.5rem] shrink-0">{t('sites.redirectStatus')}</span>
                    <span className="w-9 shrink-0" />
                  </div>
                  {siteForm.redirects.map((rule, i) => (
                    <div key={i} className="flex items-center gap-2">
                      <div className="min-w-0 flex-1">
                        <Input
                          value={rule.path}
                          onChange={(e) => setSiteForm({ ...siteForm, redirects: siteForm.redirects.map((r, j) => (j === i ? { ...r, path: e.target.value } : r)) })}
                          placeholder="/old-path"
                          className="font-mono text-xs"
                          aria-label={t('sites.redirectFrom')}
                        />
                      </div>
                      <ChevronRight size={14} className="shrink-0 text-slate-400" />
                      <div className="min-w-0 flex-1">
                        <Input
                          value={rule.target}
                          onChange={(e) => setSiteForm({ ...siteForm, redirects: siteForm.redirects.map((r, j) => (j === i ? { ...r, target: e.target.value } : r)) })}
                          placeholder="https://example.com/new"
                          className="font-mono text-xs"
                          aria-label={t('sites.redirectTo')}
                        />
                      </div>
                      <div className="w-[4.5rem] shrink-0">
                        <Select
                          value={String(rule.status)}
                          onChange={(e) => setSiteForm({ ...siteForm, redirects: siteForm.redirects.map((r, j) => (j === i ? { ...r, status: Number(e.target.value) } : r)) })}
                          aria-label={t('sites.redirectStatus')}
                        >
                          <option value="301">301</option>
                          <option value="302">302</option>
                        </Select>
                      </div>
                      <Button variant="ghost" size="sm" icon={<Trash2 size={14} className="text-red-500" />} onClick={() => setSiteForm({ ...siteForm, redirects: siteForm.redirects.filter((_, j) => j !== i) })} aria-label={t('common.delete')} />
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Advanced options (collapsible) */}
            <div className="border-t border-slate-200 pt-3 dark:border-slate-700">
              <button
                type="button"
                onClick={() => setAdvanced((v) => !v)}
                className="flex items-center gap-1.5 text-sm font-medium text-slate-600 hover:text-brand-600 dark:text-slate-300"
                aria-expanded={advanced}
              >
                <ChevronRight size={15} className={`transition-transform ${advanced ? 'rotate-90' : ''}`} />
                {t('sites.advanced')}
              </button>
              {advanced && (
                <div className="mt-3 grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <Field label={t('sites.maxBody')} hint={t('sites.maxBodyHint')}>
                    <Input
                      type="number"
                      min={0}
                      value={siteForm.max_body_mb}
                      onChange={(e) => setSiteForm({ ...siteForm, max_body_mb: Math.max(0, Number(e.target.value) || 0) })}
                    />
                  </Field>
                  <Field label={t('sites.upstreamTimeout')} hint={t('sites.upstreamTimeoutHint')}>
                    <Input
                      type="number"
                      min={1}
                      value={siteForm.upstream_timeout_secs}
                      onChange={(e) => setSiteForm({ ...siteForm, upstream_timeout_secs: Math.max(1, Number(e.target.value) || 1) })}
                    />
                  </Field>
                  <div className="sm:col-span-2">
                    <label className="flex items-start gap-2.5 text-sm text-slate-700 dark:text-slate-200">
                      <Toggle checked={siteForm.block_crawler_ua} onChange={(v) => setSiteForm({ ...siteForm, block_crawler_ua: v })} aria-label="Block crawlers" />
                      <span>{t('sites.blockCrawlers')}<span className="ml-1 block text-xs text-slate-400">{t('sites.blockCrawlersHint')}</span></span>
                    </label>
                  </div>
                  <div className="sm:col-span-2">
                    <label className="flex items-start gap-2.5 text-sm text-slate-700 dark:text-slate-200">
                      <Toggle checked={siteForm.browser_only} onChange={(v) => setSiteForm({ ...siteForm, browser_only: v })} aria-label="Browser only" />
                      <span>{t('sites.browserOnly')}<span className="ml-1 block text-xs text-slate-400">{t('sites.browserOnlyHint')}</span></span>
                    </label>
                  </div>
                  <div className="sm:col-span-2">
                    <label className="flex items-start gap-2.5 text-sm text-slate-700 dark:text-slate-200">
                      <Toggle checked={siteForm.rewrite_robots} onChange={(v) => setSiteForm({ ...siteForm, rewrite_robots: v })} aria-label="Rewrite robots.txt" />
                      <span>{t('sites.rewriteRobots')}<span className="ml-1 block text-xs text-slate-400">{t('sites.rewriteRobotsHint')}</span></span>
                    </label>
                  </div>

                  {/* IP access controls */}
                  <Field label={t('sites.blockedCountries')} hint={t('sites.blockedCountriesHint')} className="sm:col-span-2">
                    <CountryMultiSelect
                      value={siteForm.blocked_countries}
                      onChange={(codes) => setSiteForm({ ...siteForm, blocked_countries: codes })}
                      placeholder={t('sites.blockedCountriesPlaceholder')}
                    />
                  </Field>
                  <div className="sm:col-span-2">
                    <label className="flex items-start gap-2.5 text-sm text-slate-700 dark:text-slate-200">
                      <Toggle checked={siteForm.block_datacenter} onChange={(v) => setSiteForm({ ...siteForm, block_datacenter: v })} aria-label="Block datacenter IPs" />
                      <span>{t('sites.blockDatacenter')}<span className="ml-1 block text-xs text-slate-400">{t('sites.blockDatacenterHint')}</span></span>
                    </label>
                  </div>
                  <div className="sm:col-span-2">
                    <label className="flex items-start gap-2.5 text-sm text-slate-700 dark:text-slate-200">
                      <Toggle checked={siteForm.cloudflare_only} onChange={(v) => setSiteForm({ ...siteForm, cloudflare_only: v })} aria-label="Cloudflare only" />
                      <span>{t('sites.cloudflareOnly')}<span className="ml-1 block text-xs text-slate-400">{t('sites.cloudflareOnlyHint')}</span></span>
                    </label>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </Modal>

      {/* Path create / edit modal */}
      <Modal
        open={!!routeForm}
        onClose={() => setRouteForm(null)}
        title={routeForm?.id ? t('routes.editTitle') : t('routes.newTitle')}
        description={routeForm ? t('routes.underSite', { host: sites.data?.find((s) => s.id === routeForm.site_id)?.host ?? '' }) : ''}
        footer={
          <>
            <Button variant="secondary" onClick={() => setRouteForm(null)}>{t('common.cancel')}</Button>
            <Button onClick={saveRoute} loading={saving}>{routeForm?.id ? t('common.saveChanges') : t('routes.createBtn')}</Button>
          </>
        }
      >
        {routeForm && (
          <div className="space-y-4">
            <Field label={t('routes.field.path')}>
              <Input value={routeForm.path} onChange={(e) => setRouteForm({ ...routeForm, path: e.target.value })} placeholder="/" className="font-mono text-sm" />
            </Field>
            <Field label={t('routes.field.upstream')}>
              <Select value={routeForm.upstream} onChange={(e) => setRouteForm({ ...routeForm, upstream: e.target.value })}>
                <option value="" disabled>{t('routes.selectUpstream')}</option>
                {upstreams.data?.map((u) => (
                  <option key={u.id} value={u.name}>{u.name}</option>
                ))}
              </Select>
            </Field>
            <div className="flex flex-wrap gap-6 pt-1">
              <label className="flex items-center gap-2.5 text-sm text-slate-700 dark:text-slate-200">
                <Toggle checked={routeForm.waf_enabled} onChange={(v) => setRouteForm({ ...routeForm, waf_enabled: v })} aria-label="WAF" /> {t('routes.enableWaf')}
              </label>
              <label className="flex items-center gap-2.5 text-sm text-slate-700 dark:text-slate-200">
                <Toggle checked={routeForm.enabled} onChange={(v) => setRouteForm({ ...routeForm, enabled: v })} aria-label="Enabled" /> {t('common.active')}
              </label>
            </div>
          </div>
        )}
      </Modal>

      <ConfirmDialog
        open={!!siteToDelete}
        onClose={() => setSiteToDelete(null)}
        onConfirm={deleteSite}
        title={t('sites.deleteTitle')}
        confirmLabel={t('common.delete')}
        message={t('sites.deleteMsg', { host: siteToDelete?.host ?? '' })}
      />
      <ConfirmDialog
        open={!!routeToDelete}
        onClose={() => setRouteToDelete(null)}
        onConfirm={deleteRoute}
        title={t('routes.deleteTitle')}
        confirmLabel={t('common.delete')}
        message={t('routes.deleteMsg', { target: routeToDelete?.path ?? '' })}
      />
    </div>
  )
}
