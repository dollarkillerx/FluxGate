import { useEffect, useState, type ReactNode } from 'react'
import { Save, Server, RotateCw } from 'lucide-react'
import { useRpc } from '@/hooks/useRpc'
import { rpc } from '@/api/rpc'
import { useToast } from '@/context/ToastContext'
import type { Settings, SystemInfo, WafAction } from '@/types'
import { PageHeader } from '@/components/ui/PageHeader'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Toggle } from '@/components/ui/Toggle'
import { Field, Input, Select } from '@/components/ui/Field'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { StateView } from '@/components/ui/States'
import { Badge } from '@/components/ui/Badge'
import { useI18n } from '@/i18n/I18nContext'
import { formatUptime } from '@/lib/utils'

const LOG_LEVELS = ['trace', 'debug', 'info', 'warn', 'error']
const WAF_ACTIONS: WafAction[] = ['allow', 'deny', 'challenge']

export function SettingsPage() {
  const toast = useToast()
  const { t } = useI18n()
  const { data, loading, error, refetch } = useRpc<Settings>('settings.get')
  const info = useRpc<SystemInfo>('system.info')

  const [form, setForm] = useState<Settings | null>(null)
  const [saving, setSaving] = useState(false)
  const [reloadOpen, setReloadOpen] = useState(false)
  const [pw, setPw] = useState({ current: '', next: '', confirm: '' })
  const [pwBusy, setPwBusy] = useState(false)

  const changePassword = async () => {
    if (pw.next.length < 6) {
      toast.warning(t('settings.passwordTooShort'))
      return
    }
    if (pw.next !== pw.confirm) {
      toast.warning(t('settings.passwordMismatch'))
      return
    }
    setPwBusy(true)
    try {
      await rpc.call('auth.change_password', { current_password: pw.current, new_password: pw.next })
      toast.success(t('settings.passwordChanged'))
      setPw({ current: '', next: '', confirm: '' })
    } catch (e: any) {
      toast.error(t('toast.updateFailed'), e?.message)
    } finally {
      setPwBusy(false)
    }
  }

  useEffect(() => {
    if (data) setForm(structuredClone(data))
  }, [data])

  const save = async () => {
    if (!form) return
    setSaving(true)
    try {
      await rpc.call('settings.update', form)
      toast.success(t('settings.saved'), t('settings.savedDesc'))
      refetch()
    } catch (e: any) {
      toast.error(t('toast.saveFailed'), e?.message)
    } finally {
      setSaving(false)
    }
  }

  const reload = async () => {
    try {
      const res = await rpc.call<{ message: string }>('system.reload')
      toast.success(t('header.reload.success'), res.message)
    } catch (e: any) {
      toast.error(t('header.reload.failed'), e?.message)
    }
  }

  return (
    <div>
      <PageHeader
        title={t('settings.title')}
        description={t('settings.desc')}
        actions={
          <>
            <Button variant="secondary" icon={<RotateCw size={16} />} onClick={() => setReloadOpen(true)}>{t('settings.reload')}</Button>
            <Button icon={<Save size={16} />} onClick={save} loading={saving} disabled={!form}>{t('settings.saveChanges')}</Button>
          </>
        }
      />

      <StateView loading={loading} error={error} data={form} onRetry={refetch}>
        {(s) => (
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            {/* System info */}
            <Card className="lg:col-span-2">
              <CardHeader title={t('settings.system')} description={t('settings.systemDesc')} action={<Badge tone="success" dot>{t('common.online')}</Badge>} />
              <CardBody>
                {info.data ? (
                  <div className="grid grid-cols-2 gap-4 text-sm sm:grid-cols-4">
                    <Info label={t('settings.version')} value={`v${info.data.version}`} icon={<Server size={14} />} />
                    <Info label={t('settings.build')} value={info.data.build} />
                    <Info label={t('settings.pingora')} value={info.data.pingora_version} />
                    <Info label={t('settings.uptime')} value={formatUptime(info.data.uptime_secs)} />
                  </div>
                ) : null}
              </CardBody>
            </Card>

            {/* Admin */}
            <Card>
              <CardHeader title={t('settings.admin')} description={t('settings.adminDesc')} />
              <CardBody className="space-y-4">
                <Field label={t('settings.username')}>
                  <Input value={s.admin_username} onChange={(e) => setForm({ ...s, admin_username: e.target.value })} />
                </Field>
                <Field label={t('settings.email')}>
                  <Input type="email" value={s.admin_email} onChange={(e) => setForm({ ...s, admin_email: e.target.value })} />
                </Field>
              </CardBody>
            </Card>

            {/* Password */}
            <Card>
              <CardHeader title={t('settings.changePassword')} description={t('settings.changePasswordDesc')} />
              <CardBody className="space-y-4">
                <Field label={t('settings.currentPassword')}>
                  <Input type="password" autoComplete="current-password" value={pw.current} onChange={(e) => setPw({ ...pw, current: e.target.value })} />
                </Field>
                <div className="grid grid-cols-2 gap-4">
                  <Field label={t('settings.newPassword')}>
                    <Input type="password" autoComplete="new-password" value={pw.next} onChange={(e) => setPw({ ...pw, next: e.target.value })} />
                  </Field>
                  <Field label={t('settings.confirmPassword')}>
                    <Input type="password" autoComplete="new-password" value={pw.confirm} onChange={(e) => setPw({ ...pw, confirm: e.target.value })} />
                  </Field>
                </div>
                <div>
                  <Button variant="secondary" onClick={changePassword} loading={pwBusy} disabled={!pw.current || !pw.next}>
                    {t('settings.changePwBtn')}
                  </Button>
                </div>
              </CardBody>
            </Card>

            {/* Runtime / logging */}
            <Card>
              <CardHeader title={t('settings.runtime')} description={t('settings.runtimeDesc')} />
              <CardBody className="space-y-4">
                <Field label={t('settings.logLevel')}>
                  <Select value={s.log_level} onChange={(e) => setForm({ ...s, log_level: e.target.value })}>
                    {LOG_LEVELS.map((l) => (
                      <option key={l} value={l}>{l}</option>
                    ))}
                  </Select>
                </Field>
                <Row label={t('settings.hotReload')} hint={t('settings.hotReloadHint')}>
                  <Toggle checked={s.hot_reload} onChange={(v) => setForm({ ...s, hot_reload: v })} aria-label="Hot reload" />
                </Row>
              </CardBody>
            </Card>

            {/* Security */}
            <Card>
              <CardHeader title={t('settings.defaultWaf')} description={t('settings.defaultWafDesc')} />
              <CardBody className="space-y-4">
                <Field label={t('settings.defaultAction')}>
                  <Select value={s.default_waf_action} onChange={(e) => setForm({ ...s, default_waf_action: e.target.value as WafAction })}>
                    {WAF_ACTIONS.map((a) => (
                      <option key={a} value={a}>{t(`enum.wafAction.${a}`)}</option>
                    ))}
                  </Select>
                </Field>
                {s.default_waf_action === 'deny' && (
                  <p className="rounded-md bg-amber-50 px-3 py-2 text-xs text-amber-700 dark:bg-amber-500/10 dark:text-amber-400">
                    {t('settings.denyWarning')}
                  </p>
                )}
              </CardBody>
            </Card>

            {/* ACME */}
            <Card>
              <CardHeader title={t('settings.acme')} description={t('settings.acmeDesc')} />
              <CardBody className="space-y-4">
                <Row label={t('settings.enableAcme')}>
                  <Toggle checked={s.acme.enabled} onChange={(v) => setForm({ ...s, acme: { ...s.acme, enabled: v } })} aria-label="ACME" />
                </Row>
                <Field label={t('settings.directoryUrl')}>
                  <Input value={s.acme.directory_url} onChange={(e) => setForm({ ...s, acme: { ...s.acme, directory_url: e.target.value } })} className="font-mono text-xs" />
                </Field>
                <Field label={t('settings.accountEmail')}>
                  <Input type="email" value={s.acme.email} onChange={(e) => setForm({ ...s, acme: { ...s.acme, email: e.target.value } })} />
                </Field>
                <Row label={t('settings.agreeTos')}>
                  <Toggle checked={s.acme.agree_tos} onChange={(v) => setForm({ ...s, acme: { ...s.acme, agree_tos: v } })} aria-label="Agree TOS" />
                </Row>
              </CardBody>
            </Card>

            {/* Runtime params */}
            <Card className="lg:col-span-2">
              <CardHeader title={t('settings.params')} description={t('settings.paramsDesc')} />
              <CardBody>
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                  <Field label={t('settings.workerThreads')}>
                    <Input type="number" value={s.worker_threads} onChange={(e) => setForm({ ...s, worker_threads: Number(e.target.value) })} />
                  </Field>
                  <Field label={t('settings.maxConn')}>
                    <Input type="number" value={s.max_connections} onChange={(e) => setForm({ ...s, max_connections: Number(e.target.value) })} />
                  </Field>
                  <Field label={t('settings.reqTimeout')}>
                    <Input type="number" value={s.request_timeout_secs} onChange={(e) => setForm({ ...s, request_timeout_secs: Number(e.target.value) })} />
                  </Field>
                </div>
              </CardBody>
            </Card>
          </div>
        )}
      </StateView>

      <ConfirmDialog
        open={reloadOpen}
        onClose={() => setReloadOpen(false)}
        onConfirm={reload}
        tone="primary"
        title={t('settings.reloadTitle')}
        confirmLabel={t('header.reload.confirm')}
        message={t('settings.reloadMsg')}
      />
    </div>
  )
}

function Info({ label, value, icon }: { label: string; value: string; icon?: JSX.Element }) {
  return (
    <div>
      <div className="flex items-center gap-1.5 text-xs text-slate-400">{icon}{label}</div>
      <div className="mt-0.5 font-medium text-slate-800 dark:text-slate-100">{value}</div>
    </div>
  )
}

function Row({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4">
      <div>
        <div className="text-sm text-slate-700 dark:text-slate-200">{label}</div>
        {hint && <div className="text-xs text-slate-400">{hint}</div>}
      </div>
      {children}
    </div>
  )
}
