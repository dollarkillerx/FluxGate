import { useEffect, useState } from 'react'
import { Plus, Trash2, ShieldX, ShieldCheck, Ban } from 'lucide-react'
import { useRpc } from '@/hooks/useRpc'
import { rpc } from '@/api/rpc'
import { useToast } from '@/context/ToastContext'
import { useI18n } from '@/i18n/I18nContext'
import type { IpAccessData, IpListEntry } from '@/types'
import { PageHeader } from '@/components/ui/PageHeader'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Toggle } from '@/components/ui/Toggle'
import { Field, Input, Select } from '@/components/ui/Field'
import { Badge } from '@/components/ui/Badge'
import { Spinner, ErrorState } from '@/components/ui/States'

const DURATIONS = [0, 3600, 5 * 3600, 12 * 3600, 24 * 3600, 7 * 24 * 3600]

export function AccessPage() {
  const { t } = useI18n()
  const toast = useToast()
  const { data, loading, error, refetch } = useRpc<IpAccessData>('ip.list', {}, [], 8000)

  // Auto-ban settings (local mirror of the fetched config).
  const [enabled, setEnabled] = useState(false)
  const [threshold, setThreshold] = useState(20)
  const [duration, setDuration] = useState(5 * 3600)
  const [savingCfg, setSavingCfg] = useState(false)
  useEffect(() => {
    if (data) {
      setEnabled(data.auto_ban_enabled)
      setThreshold(data.auto_ban_threshold)
      setDuration(data.auto_ban_duration_secs)
    }
  }, [data])

  const saveCfg = async () => {
    setSavingCfg(true)
    try {
      await rpc.call('settings.update', {
        auto_ban_enabled: enabled,
        auto_ban_threshold: Math.max(1, threshold),
        auto_ban_duration_secs: Math.max(0, duration),
      })
      toast.success(t('access.cfgSaved'))
      refetch()
    } catch (e: any) {
      toast.error(t('toast.saveFailed'), e?.message)
    } finally {
      setSavingCfg(false)
    }
  }

  const durationLabel = (secs: number) =>
    secs === 0 ? t('access.permanent') : t('access.hours', { n: String(Math.round(secs / 3600)) })

  const banExpiry = (expires_at: number) => {
    if (expires_at === 0) return t('access.permanent')
    const mins = Math.max(0, Math.round((expires_at - Date.now() / 1000) / 60))
    return mins >= 60 ? t('access.inHours', { n: String(Math.round(mins / 60)) }) : t('access.inMins', { n: String(mins) })
  }

  return (
    <div>
      <PageHeader title={t('access.title')} description={t('access.desc')} />

      {error && !data ? (
        <ErrorState message={error} onRetry={refetch} />
      ) : loading && !data ? (
        <Spinner />
      ) : data ? (
        <div className="space-y-4">
          {/* Auto-ban settings */}
          <Card>
            <CardHeader title={t('access.autoBan')} description={t('access.autoBanDesc')} />
            <CardBody>
              <label className="mb-4 flex items-center gap-2.5 text-sm text-slate-700 dark:text-slate-200">
                <Toggle checked={enabled} onChange={setEnabled} aria-label="Auto-ban" /> {t('access.enable')}
              </label>
              <div className="grid grid-cols-1 items-start gap-4 sm:max-w-xl sm:grid-cols-2">
                <Field label={t('access.threshold')} hint={t('access.thresholdHint')}>
                  <Input type="number" min={1} value={threshold} disabled={!enabled} onChange={(e) => setThreshold(Math.max(1, Number(e.target.value) || 1))} />
                </Field>
                <Field label={t('access.duration')}>
                  <Select value={String(duration)} disabled={!enabled} onChange={(e) => setDuration(Number(e.target.value))}>
                    {(DURATIONS.includes(duration) ? DURATIONS : [duration, ...DURATIONS]).map((s) => (
                      <option key={s} value={s}>{durationLabel(s)}</option>
                    ))}
                  </Select>
                </Field>
              </div>
              <div className="mt-4">
                <Button onClick={saveCfg} loading={savingCfg}>{t('common.saveChanges')}</Button>
              </div>
              <p className="mt-3 text-xs text-amber-600 dark:text-amber-400">{t('access.realIpNote')}</p>
            </CardBody>
          </Card>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <IpList
              icon={<ShieldCheck size={16} className="text-emerald-500" />}
              title={t('access.whitelist')}
              desc={t('access.whitelistDesc')}
              entries={data.whitelist}
              addMethod="ip.whitelist.add"
              removeMethod="ip.whitelist.remove"
              onChange={refetch}
            />
            <IpList
              icon={<ShieldX size={16} className="text-red-500" />}
              title={t('access.blacklist')}
              desc={t('access.blacklistDesc')}
              entries={data.blacklist}
              addMethod="ip.blacklist.add"
              removeMethod="ip.blacklist.remove"
              onChange={refetch}
            />
          </div>

          {/* Active auto-bans */}
          <Card>
            <CardHeader title={t('access.activeBans')} description={t('access.activeBansDesc')} />
            <CardBody className="p-0">
              {data.bans.length === 0 ? (
                <p className="py-8 text-center text-sm text-slate-400">{t('access.noBans')}</p>
              ) : (
                <div className="divide-y divide-slate-100 dark:divide-slate-800">
                  {data.bans.map((b) => (
                    <div key={b.ip} className="flex items-center justify-between gap-3 px-5 py-2.5">
                      <div className="flex min-w-0 items-center gap-2.5">
                        <Ban size={14} className="shrink-0 text-red-500" />
                        <span className="truncate font-mono text-sm text-slate-700 dark:text-slate-200">{b.ip}</span>
                        <Badge tone="neutral">{t('access.denies', { n: String(b.deny_count) })}</Badge>
                        <span className="text-xs text-slate-400">{banExpiry(b.expires_at)}</span>
                      </div>
                      <Button variant="ghost" size="sm" onClick={async () => {
                        try { await rpc.call('ip.ban.remove', { ip: b.ip }); toast.success(t('access.unbanned'), b.ip); refetch() }
                        catch (e: any) { toast.error(t('toast.updateFailed'), e?.message) }
                      }}>{t('access.unban')}</Button>
                    </div>
                  ))}
                </div>
              )}
            </CardBody>
          </Card>
        </div>
      ) : null}
    </div>
  )
}

function IpList({ icon, title, desc, entries, addMethod, removeMethod, onChange }: {
  icon: React.ReactNode
  title: string
  desc: string
  entries: IpListEntry[]
  addMethod: string
  removeMethod: string
  onChange: () => void
}) {
  const { t } = useI18n()
  const toast = useToast()
  const [value, setValue] = useState('')
  const [note, setNote] = useState('')
  const [adding, setAdding] = useState(false)

  const add = async () => {
    if (!value.trim()) return
    setAdding(true)
    try {
      await rpc.call(addMethod, { value: value.trim(), note: note.trim() })
      setValue(''); setNote(''); onChange()
    } catch (e: any) {
      toast.error(t('toast.saveFailed'), e?.message)
    } finally {
      setAdding(false)
    }
  }
  const remove = async (v: string) => {
    try { await rpc.call(removeMethod, { value: v }); onChange() }
    catch (e: any) { toast.error(t('toast.deleteFailed'), e?.message) }
  }

  return (
    <Card>
      <CardHeader title={<span className="flex items-center gap-2">{icon}{title}</span>} description={desc} />
      <CardBody>
        <div className="flex gap-2">
          <Input value={value} onChange={(e) => setValue(e.target.value)} placeholder="203.0.113.7 / 10.0.0.0/24" className="font-mono text-xs" onKeyDown={(e) => e.key === 'Enter' && add()} />
          <Input value={note} onChange={(e) => setNote(e.target.value)} placeholder={t('access.notePlaceholder')} className="max-w-[40%]" onKeyDown={(e) => e.key === 'Enter' && add()} />
          <Button icon={<Plus size={15} />} onClick={add} loading={adding} />
        </div>
        <div className="mt-3 divide-y divide-slate-100 dark:divide-slate-800">
          {entries.length === 0 ? (
            <p className="py-6 text-center text-sm text-slate-400">{t('access.empty')}</p>
          ) : (
            entries.map((e) => (
              <div key={e.value} className="flex items-center justify-between gap-2 py-2">
                <div className="min-w-0">
                  <span className="font-mono text-sm text-slate-700 dark:text-slate-200">{e.value}</span>
                  {e.note ? <span className="ml-2 truncate text-xs text-slate-400">{e.note}</span> : null}
                </div>
                <Button variant="ghost" size="sm" icon={<Trash2 size={14} className="text-red-500" />} onClick={() => remove(e.value)} aria-label="Remove" />
              </div>
            ))
          )}
        </div>
      </CardBody>
    </Card>
  )
}
