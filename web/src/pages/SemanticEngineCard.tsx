import { useEffect, useState } from 'react'
import { Plus, Trash2, ShieldCheck } from 'lucide-react'
import { useRpc } from '@/hooks/useRpc'
import { rpc } from '@/api/rpc'
import { useToast } from '@/context/ToastContext'
import type { AnomalyConfig, RiskAction, WafModule, WafSemanticConfig } from '@/types'
import { Card, CardHeader, CardBody } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Toggle } from '@/components/ui/Toggle'
import { Badge } from '@/components/ui/Badge'
import { Field, Input, Select } from '@/components/ui/Field'
import { StateView } from '@/components/ui/States'

const MODULES: { key: WafModule; label: string; blurb: string }[] = [
  { key: 'sqli', label: 'SQL Injection', blurb: 'Tokenized SQL structure (tautologies, UNION, stacked, comments).' },
  { key: 'xss', label: 'XSS', blurb: 'HTML-structure aware: dangerous tags, event handlers, URIs.' },
  { key: 'traversal', label: 'Path Traversal', blurb: 'Structural ../ resolution and sensitive-file targets.' },
  { key: 'cmdi', label: 'Command Injection', blurb: 'Shell command position after operators / substitutions.' },
  { key: 'ssrf', label: 'SSRF', blurb: 'Cloud-metadata and internal/loopback targets in URLs.' },
  { key: 'proto', label: 'Protocol', blurb: 'Null bytes and CRLF header injection.' },
  { key: 'ssti', label: 'Template Injection', blurb: 'Template-expression payloads ({{7*7}}, ${...}) and known gadgets.' },
  { key: 'nosql', label: 'NoSQL Injection', blurb: 'MongoDB operators ($where, $ne, $gt…) in operator position.' },
  { key: 'xxe', label: 'XXE', blurb: 'DOCTYPE/ENTITY declarations that pull external resources.' },
  { key: 'deser', label: 'Deserialization', blurb: 'Serialized object streams (Java rO0AB, PHP O:…, pickle, .NET, Ruby, Node).' },
  { key: 'php', label: 'PHP Injection', blurb: 'PHP function calls (system()/shell_exec()…), <?php tags, superglobals.' },
  { key: 'java', label: 'Java / OGNL / SpEL', blurb: 'JVM expression & reflection injection (OGNL, Runtime, ClassLoader, forName).' },
]

const RISK_ACTIONS: RiskAction[] = ['block', 'challenge', 'log']
const RISK_LEVELS: ('high' | 'medium' | 'low')[] = ['high', 'medium', 'low']

function defaultModule() {
  return { enabled: true, high: 'block' as RiskAction, medium: 'challenge' as RiskAction, low: 'log' as RiskAction }
}

export function SemanticEngineCard() {
  const toast = useToast()
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
      toast.success('Detection engine updated')
      refetch()
    } catch (e: any) {
      toast.error('Save failed', e?.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Card>
      <CardHeader
        title={
          <span className="flex items-center gap-2">
            <ShieldCheck size={16} className="text-emerald-500" /> Semantic detection engine
          </span>
        }
        description="Structure-aware detection that parses each request value instead of keyword-matching — far fewer false positives. Runs after the regex policy rules."
      />
      <CardBody>
        <StateView loading={loading} error={error} data={cfg} onRetry={refetch}>
          {(c) => (
            <div className="space-y-5">
            {/* Mode */}
            <div className="flex items-center justify-between rounded-lg border border-slate-200 p-3 dark:border-slate-700">
              <div>
                <div className="text-sm font-medium text-slate-800 dark:text-slate-100">Mode</div>
                <div className="text-xs text-slate-500">
                  {c.mode === 'monitor'
                    ? 'Monitor — detections are logged but never blocked (safe rollout).'
                    : 'Block — enforce per-module risk actions below.'}
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Badge tone={c.mode === 'block' ? 'success' : 'warning'} dot>
                  {c.mode === 'block' ? 'Blocking' : 'Monitor'}
                </Badge>
                <Toggle
                  checked={c.mode === 'block'}
                  onChange={(v) => setCfg({ ...c, mode: v ? 'block' : 'monitor' })}
                  aria-label="Blocking mode"
                />
              </div>
            </div>

            {/* Per-module config */}
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs uppercase tracking-wide text-slate-400">
                    <th className="pb-2">Module</th>
                    <th className="pb-2 text-center">On</th>
                    <th className="pb-2">High risk</th>
                    <th className="pb-2">Medium</th>
                    <th className="pb-2">Low</th>
                  </tr>
                </thead>
                <tbody>
                  {MODULES.map((m) => {
                    const mc = c.modules?.[m.key] ?? defaultModule()
                    return (
                      <tr key={m.key} className="border-t border-slate-100 dark:border-slate-800">
                        <td className="py-2.5 pr-3">
                          <div className="font-medium text-slate-800 dark:text-slate-100">{m.label}</div>
                          <div className="max-w-sm text-xs text-slate-400">{m.blurb}</div>
                        </td>
                        <td className="text-center">
                          <Toggle checked={mc.enabled} onChange={(v) => updateModule(m.key, { enabled: v })} aria-label={`${m.label} enabled`} />
                        </td>
                        {RISK_LEVELS.map((lvl) => (
                          <td key={lvl} className="py-2 pr-2">
                            <Select
                              value={mc[lvl]}
                              disabled={!mc.enabled}
                              onChange={(e) => updateModule(m.key, { [lvl]: e.target.value as RiskAction })}
                            >
                              {RISK_ACTIONS.map((a) => (
                                <option key={a} value={a}>{a}</option>
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
                      <div className="text-sm font-medium text-slate-800 dark:text-slate-100">Anomaly scoring</div>
                      <div className="max-w-md text-xs text-slate-500">
                        Combine weak signals: each detection adds to a score (low 2 · medium 3 · high 5).
                        When a request's total crosses the threshold, the action is escalated — so several
                        individually-minor hits together get challenged or blocked.
                      </div>
                    </div>
                    <Toggle checked={an.enabled} onChange={(v) => updateAnomaly({ enabled: v })} aria-label="Anomaly scoring enabled" />
                  </div>
                  {an.enabled && (
                    <div className="mt-3 grid grid-cols-2 gap-3">
                      <Field label="Threshold">
                        <Input
                          type="number"
                          min={1}
                          value={an.threshold}
                          onChange={(e) => updateAnomaly({ threshold: Math.max(1, Number(e.target.value) || 1) })}
                        />
                      </Field>
                      <Field label="Escalate to">
                        <Select value={an.action} onChange={(e) => updateAnomaly({ action: e.target.value as RiskAction })}>
                          {RISK_ACTIONS.map((a) => (
                            <option key={a} value={a}>{a}</option>
                          ))}
                        </Select>
                      </Field>
                    </div>
                  )}
                </div>
              )
            })()}

            <div className="flex justify-end">
              <Button onClick={save} loading={saving}>Save engine settings</Button>
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
      toast.error('Add failed', 'Set at least a module, path prefix, or parameter.')
      return
    }
    try {
      await rpc.call('waf.exception.create', {
        module: form.module || undefined,
        path_prefix: form.path_prefix,
        param: form.param || undefined,
        note: form.note,
      })
      toast.success('Exception added')
      setForm({ module: '', path_prefix: '', param: '', note: '' })
      setAdding(false)
      onChanged()
    } catch (e: any) {
      toast.error('Add failed', e?.message)
    }
  }

  const remove = async (id: string) => {
    try {
      await rpc.call('waf.exception.delete', { id })
      toast.success('Exception removed')
      onChanged()
    } catch (e: any) {
      toast.error('Delete failed', e?.message)
    }
  }

  return (
    <div className="rounded-lg border border-slate-200 p-3 dark:border-slate-700">
      <div className="mb-2 flex items-center justify-between">
        <div className="text-sm font-medium text-slate-800 dark:text-slate-100">
          Exceptions <span className="text-xs font-normal text-slate-400">— accepted false positives</span>
        </div>
        <Button variant="ghost" size="sm" icon={<Plus size={14} />} onClick={() => setAdding((v) => !v)}>
          Add
        </Button>
      </div>

      {adding && (
        <div className="mb-3 grid grid-cols-2 gap-2 rounded-md bg-slate-50 p-2 dark:bg-slate-800/50">
          <Field label="Module (optional)">
            <Select value={form.module} onChange={(e) => setForm({ ...form, module: e.target.value })}>
              <option value="">Any</option>
              {MODULES.map((m) => (
                <option key={m.key} value={m.key}>{m.label}</option>
              ))}
            </Select>
          </Field>
          <Field label="Path prefix">
            <Input value={form.path_prefix} onChange={(e) => setForm({ ...form, path_prefix: e.target.value })} placeholder="/api/search" />
          </Field>
          <Field label="Parameter (optional)">
            <Input value={form.param} onChange={(e) => setForm({ ...form, param: e.target.value })} placeholder="q" />
          </Field>
          <Field label="Note">
            <Input value={form.note} onChange={(e) => setForm({ ...form, note: e.target.value })} placeholder="known FP on search" />
          </Field>
          <div className="col-span-2 flex justify-end">
            <Button size="sm" onClick={add}>Save exception</Button>
          </div>
        </div>
      )}

      {exceptions.length === 0 ? (
        <div className="py-2 text-xs text-slate-400">No exceptions. Detections from the engine apply everywhere.</div>
      ) : (
        <ul className="divide-y divide-slate-100 dark:divide-slate-800">
          {exceptions.map((e) => (
            <li key={e.id} className="flex items-center justify-between py-2 text-sm">
              <div className="flex items-center gap-2">
                <Badge tone="neutral">{e.module ?? 'any'}</Badge>
                <span className="font-mono text-xs text-slate-500">{e.path_prefix || '/*'}{e.param ? ` · ${e.param}` : ''}</span>
                {e.note && <span className="text-xs text-slate-400">— {e.note}</span>}
              </div>
              <Button variant="ghost" size="sm" icon={<Trash2 size={14} className="text-red-500" />} onClick={() => remove(e.id)} aria-label="Delete exception" />
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
