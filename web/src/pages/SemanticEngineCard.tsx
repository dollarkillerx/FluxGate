import { useEffect, useState } from 'react'
import { Plus, Trash2, ShieldCheck } from 'lucide-react'
import { useRpc } from '@/hooks/useRpc'
import { rpc } from '@/api/rpc'
import { useToast } from '@/context/ToastContext'
import { useI18n } from '@/i18n/I18nContext'
import type { AnomalyConfig, RiskAction, WafModule, WafSemanticConfig } from '@/types'
import { Card, CardHeader, CardBody } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Toggle } from '@/components/ui/Toggle'
import { Badge } from '@/components/ui/Badge'
import { Field, Input, Select } from '@/components/ui/Field'
import { StateView } from '@/components/ui/States'

// Detection modules, in display order. Labels + blurbs are localized via
// `waf.sem.mod.<key>.{label,blurb}` so the card respects the chosen language.
const MODULE_KEYS: WafModule[] = [
  'sqli', 'xss', 'traversal', 'cmdi', 'ssrf', 'proto',
  'ssti', 'nosql', 'xxe', 'deser', 'php', 'java',
]

const RISK_ACTIONS: RiskAction[] = ['block', 'challenge', 'log']
const RISK_LEVELS: ('high' | 'medium' | 'low')[] = ['high', 'medium', 'low']

function defaultModule() {
  return { enabled: true, high: 'block' as RiskAction, medium: 'challenge' as RiskAction, low: 'log' as RiskAction }
}

export function SemanticEngineCard() {
  const toast = useToast()
  const { t } = useI18n()
  const { data, loading, error, refetch } = useRpc<WafSemanticConfig>('waf.semantic.get')
  const [cfg, setCfg] = useState<WafSemanticConfig | null>(null)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (data) setCfg(structuredClone(data))
  }, [data])

  const moduleCfg = (m: WafModule) => cfg?.modules?.[m] ?? defaultModule()

  const updateModule = (m: WafModule, patch: Partial<ReturnType<typeof defaultModule>>) => {
    if (!cfg) return
    const modules = { ...cfg.modules, [m]: { ...moduleCfg(m), ...patch } }
    setCfg({ ...cfg, modules })
  }

  const defaultAnomaly = (): AnomalyConfig => ({ enabled: false, threshold: 6, action: 'challenge' })
  const updateAnomaly = (patch: Partial<AnomalyConfig>) => {
    if (!cfg) return
    setCfg({ ...cfg, anomaly: { ...(cfg.anomaly ?? defaultAnomaly()), ...patch } })
  }

  const save = async () => {
    if (!cfg) return
    setSaving(true)
    try {
      await rpc.call('waf.semantic.update', cfg)
      toast.success(t('waf.sem.toast.updated'))
      refetch()
    } catch (e: any) {
      toast.error(t('waf.sem.toast.saveFail'), e?.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Card>
      <CardHeader
        title={
          <span className="flex items-center gap-2">
            <ShieldCheck size={16} className="text-emerald-500" /> {t('waf.sem.title')}
          </span>
        }
        description={t('waf.sem.desc')}
      />
      <CardBody>
        <StateView loading={loading} error={error} data={cfg} onRetry={refetch}>
          {(c) => (
            <div className="space-y-5">
            {/* Mode */}
            <div className="flex items-center justify-between rounded-lg border border-slate-200 p-3 dark:border-slate-700">
              <div>
                <div className="text-sm font-medium text-slate-800 dark:text-slate-100">{t('waf.sem.mode')}</div>
                <div className="text-xs text-slate-500">
                  {c.mode === 'monitor' ? t('waf.sem.mode.monitor') : t('waf.sem.mode.block')}
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Badge tone={c.mode === 'block' ? 'success' : 'warning'} dot>
                  {c.mode === 'block' ? t('waf.sem.badge.block') : t('waf.sem.badge.monitor')}
                </Badge>
                <Toggle
                  checked={c.mode === 'block'}
                  onChange={(v) => setCfg({ ...c, mode: v ? 'block' : 'monitor' })}
                  aria-label={t('waf.sem.mode')}
                />
              </div>
            </div>

            {/* Per-module config */}
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs uppercase tracking-wide text-slate-400">
                    <th className="pb-2">{t('waf.sem.col.module')}</th>
                    <th className="pb-2 text-center">{t('waf.sem.col.on')}</th>
                    <th className="pb-2">{t('waf.sem.col.high')}</th>
                    <th className="pb-2">{t('waf.sem.col.medium')}</th>
                    <th className="pb-2">{t('waf.sem.col.low')}</th>
                  </tr>
                </thead>
                <tbody>
                  {MODULE_KEYS.map((key) => {
                    const mc = c.modules?.[key] ?? defaultModule()
                    const label = t(`waf.sem.mod.${key}.label`)
                    return (
                      <tr key={key} className="border-t border-slate-100 dark:border-slate-800">
                        <td className="py-2.5 pr-3">
                          <div className="font-medium text-slate-800 dark:text-slate-100">{label}</div>
                          <div className="max-w-sm text-xs text-slate-400">{t(`waf.sem.mod.${key}.blurb`)}</div>
                        </td>
                        <td className="text-center">
                          <Toggle checked={mc.enabled} onChange={(v) => updateModule(key, { enabled: v })} aria-label={label} />
                        </td>
                        {RISK_LEVELS.map((lvl) => (
                          <td key={lvl} className="py-2 pr-2">
                            <Select
                              value={mc[lvl]}
                              disabled={!mc.enabled}
                              onChange={(e) => updateModule(key, { [lvl]: e.target.value as RiskAction })}
                            >
                              {RISK_ACTIONS.map((a) => (
                                <option key={a} value={a}>{t(`waf.sem.action.${a}`)}</option>
                              ))}
                            </Select>
                          </td>
                        ))}
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>

            {/* Anomaly scoring */}
            {(() => {
              const an = c.anomaly ?? defaultAnomaly()
              return (
                <div className="rounded-lg border border-slate-200 p-3 dark:border-slate-700">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <div className="text-sm font-medium text-slate-800 dark:text-slate-100">{t('waf.sem.anomaly')}</div>
                      <div className="max-w-md text-xs text-slate-500">{t('waf.sem.anomaly.desc')}</div>
                    </div>
                    <Toggle checked={an.enabled} onChange={(v) => updateAnomaly({ enabled: v })} aria-label={t('waf.sem.anomaly')} />
                  </div>
                  {an.enabled && (
                    <div className="mt-3 grid grid-cols-2 gap-3">
                      <Field label={t('waf.sem.anomaly.threshold')}>
                        <Input
                          type="number"
                          min={1}
                          value={an.threshold}
                          onChange={(e) => updateAnomaly({ threshold: Math.max(1, Number(e.target.value) || 1) })}
                        />
                      </Field>
                      <Field label={t('waf.sem.anomaly.escalate')}>
                        <Select value={an.action} onChange={(e) => updateAnomaly({ action: e.target.value as RiskAction })}>
                          {RISK_ACTIONS.map((a) => (
                            <option key={a} value={a}>{t(`waf.sem.action.${a}`)}</option>
                          ))}
                        </Select>
                      </Field>
                    </div>
                  )}
                </div>
              )
            })()}

            <div className="flex justify-end">
              <Button onClick={save} loading={saving}>{t('waf.sem.save')}</Button>
            </div>

            <ExceptionsSection onChanged={refetch} exceptions={c.exceptions ?? []} />
          </div>
          )}
        </StateView>
      </CardBody>
    </Card>
  )
}

function ExceptionsSection({ exceptions, onChanged }: { exceptions: WafSemanticConfig['exceptions']; onChanged: () => void }) {
  const toast = useToast()
  const { t } = useI18n()
  const [adding, setAdding] = useState(false)
  const [form, setForm] = useState<{ module: string; path_prefix: string; param: string; note: string }>({
    module: '',
    path_prefix: '',
    param: '',
    note: '',
  })

  const add = async () => {
    // An exception with no scope matches everything and would disable the engine.
    if (!form.module && !form.path_prefix.trim() && !form.param.trim()) {
      toast.error(t('waf.sem.exc.toast.addFail'), t('waf.sem.exc.scopeRequired'))
      return
    }
    try {
      await rpc.call('waf.exception.create', {
        module: form.module || undefined,
        path_prefix: form.path_prefix,
        param: form.param || undefined,
        note: form.note,
      })
      toast.success(t('waf.sem.exc.toast.added'))
      setForm({ module: '', path_prefix: '', param: '', note: '' })
      setAdding(false)
      onChanged()
    } catch (e: any) {
      toast.error(t('waf.sem.exc.toast.addFail'), e?.message)
    }
  }

  const remove = async (id: string) => {
    try {
      await rpc.call('waf.exception.delete', { id })
      toast.success(t('waf.sem.exc.toast.removed'))
      onChanged()
    } catch (e: any) {
      toast.error(t('waf.sem.exc.toast.deleteFail'), e?.message)
    }
  }

  return (
    <div className="rounded-lg border border-slate-200 p-3 dark:border-slate-700">
      <div className="mb-2 flex items-center justify-between">
        <div className="text-sm font-medium text-slate-800 dark:text-slate-100">
          {t('waf.sem.exc.title')} <span className="text-xs font-normal text-slate-400">— {t('waf.sem.exc.subtitle')}</span>
        </div>
        <Button variant="ghost" size="sm" icon={<Plus size={14} />} onClick={() => setAdding((v) => !v)}>
          {t('waf.sem.exc.add')}
        </Button>
      </div>

      {adding && (
        <div className="mb-3 grid grid-cols-2 gap-2 rounded-md bg-slate-50 p-2 dark:bg-slate-800/50">
          <Field label={t('waf.sem.exc.module')}>
            <Select value={form.module} onChange={(e) => setForm({ ...form, module: e.target.value })}>
              <option value="">{t('waf.sem.exc.any')}</option>
              {MODULE_KEYS.map((key) => (
                <option key={key} value={key}>{t(`waf.sem.mod.${key}.label`)}</option>
              ))}
            </Select>
          </Field>
          <Field label={t('waf.sem.exc.path')}>
            <Input value={form.path_prefix} onChange={(e) => setForm({ ...form, path_prefix: e.target.value })} placeholder="/api/search" />
          </Field>
          <Field label={t('waf.sem.exc.param')}>
            <Input value={form.param} onChange={(e) => setForm({ ...form, param: e.target.value })} placeholder="q" />
          </Field>
          <Field label={t('waf.sem.exc.note')}>
            <Input value={form.note} onChange={(e) => setForm({ ...form, note: e.target.value })} />
          </Field>
          <div className="col-span-2 flex justify-end">
            <Button size="sm" onClick={add}>{t('waf.sem.exc.save')}</Button>
          </div>
        </div>
      )}

      {exceptions.length === 0 ? (
        <div className="py-2 text-xs text-slate-400">{t('waf.sem.exc.empty')}</div>
      ) : (
        <ul className="divide-y divide-slate-100 dark:divide-slate-800">
          {exceptions.map((e) => (
            <li key={e.id} className="flex items-center justify-between py-2 text-sm">
              <div className="flex items-center gap-2">
                <Badge tone="neutral">{e.module ?? t('waf.sem.exc.any')}</Badge>
                <span className="font-mono text-xs text-slate-500">{e.path_prefix || '/*'}{e.param ? ` · ${e.param}` : ''}</span>
                {e.note && <span className="text-xs text-slate-400">— {e.note}</span>}
              </div>
              <Button variant="ghost" size="sm" icon={<Trash2 size={14} className="text-red-500" />} onClick={() => remove(e.id)} aria-label={t('common.delete')} />
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
