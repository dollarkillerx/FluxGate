import { useMemo, useState } from 'react'
import { createColumnHelper } from '@tanstack/react-table'
import { Plus, Pencil, Trash2 } from 'lucide-react'
import { useRpc } from '@/hooks/useRpc'
import { rpc } from '@/api/rpc'
import { useToast } from '@/context/ToastContext'
import { useI18n } from '@/i18n/I18nContext'
import type { SecurityEvent, WafAction, WafMatchType, WafRule } from '@/types'
import { PageHeader } from '@/components/ui/PageHeader'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Toggle } from '@/components/ui/Toggle'
import { Modal } from '@/components/ui/Modal'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { Field, Input, Select, Textarea } from '@/components/ui/Field'
import { DataTable } from '@/components/ui/DataTable'
import { StateView, Spinner } from '@/components/ui/States'
import { formatNumber, timeAgo } from '@/lib/utils'
import { wafActionTone } from '@/lib/status'

const col = createColumnHelper<WafRule>()

const MATCH_TYPES: WafMatchType[] = ['ip', 'path', 'header', 'method', 'geo', 'rate_limit']
const ACTIONS: WafAction[] = ['allow', 'deny', 'challenge']

interface WafForm {
  id?: string
  name: string
  description: string
  match_type: WafMatchType
  pattern: string
  action: WafAction
  priority: number
  enabled: boolean
}

const emptyForm: WafForm = { name: '', description: '', match_type: 'path', pattern: '', action: 'deny', priority: 50, enabled: true }

export function WafRulesPage() {
  const toast = useToast()
  const { t } = useI18n()
  const { data, loading, error, refetch } = useRpc<WafRule[]>('waf.rule.list')
  const events = useRpc<SecurityEvent[]>('waf.event.list', { limit: 8 })

  const [formOpen, setFormOpen] = useState(false)
  const [form, setForm] = useState<WafForm>(emptyForm)
  const [saving, setSaving] = useState(false)
  const [toDelete, setToDelete] = useState<WafRule | null>(null)

  const openCreate = () => {
    setForm(emptyForm)
    setFormOpen(true)
  }
  const openEdit = (r: WafRule) => {
    setForm({ ...r })
    setFormOpen(true)
  }

  const save = async () => {
    if (!form.name.trim()) {
      toast.warning(t('waf.nameRequired'))
      return
    }
    setSaving(true)
    try {
      await rpc.call(form.id ? 'waf.rule.update' : 'waf.rule.create', form)
      toast.success(form.id ? t('waf.updated') : t('waf.created'), form.name)
      setFormOpen(false)
      refetch()
    } catch (e: any) {
      toast.error(t('toast.saveFailed'), e?.message)
    } finally {
      setSaving(false)
    }
  }

  const remove = async () => {
    if (!toDelete) return
    try {
      await rpc.call('waf.rule.delete', { id: toDelete.id })
      toast.success(t('waf.deleted'), toDelete.name)
      refetch()
    } catch (e: any) {
      toast.error(t('toast.deleteFailed'), e?.message)
    }
  }

  const toggleEnabled = async (r: WafRule, next: boolean) => {
    try {
      await rpc.call(next ? 'waf.rule.enable' : 'waf.rule.disable', { id: r.id })
      toast.success(next ? t('waf.enabledToast') : t('waf.disabledToast'), r.name)
      refetch()
    } catch (e: any) {
      toast.error(t('toast.updateFailed'), e?.message)
    }
  }

  const columns = useMemo(
    () => [
      col.accessor('name', {
        header: t('waf.col.rule'),
        cell: (c) => (
          <div>
            <div className="font-medium text-slate-800 dark:text-slate-100">{c.getValue()}</div>
            <div className="max-w-xs truncate font-mono text-xs text-slate-400">{c.row.original.pattern}</div>
          </div>
        ),
      }),
      col.accessor('match_type', {
        header: t('waf.col.match'),
        cell: (c) => <Badge tone="neutral">{t(`enum.matchType.${c.getValue()}`)}</Badge>,
      }),
      col.accessor('action', {
        header: t('waf.col.action'),
        cell: (c) => <Badge tone={wafActionTone(c.getValue())} dot>{t(`enum.wafAction.${c.getValue()}`)}</Badge>,
      }),
      col.accessor('priority', {
        header: t('waf.col.priority'),
        cell: (c) => <span className="tabular-nums">{c.getValue()}</span>,
      }),
      col.accessor('hit_count', {
        header: t('waf.col.hits'),
        cell: (c) => <span className="tabular-nums">{formatNumber(c.getValue())}</span>,
      }),
      col.accessor('enabled', {
        header: t('waf.col.enabled'),
        cell: (c) => <Toggle checked={c.getValue()} onChange={(v) => toggleEnabled(c.row.original, v)} aria-label="Toggle rule" />,
      }),
      col.display({
        id: 'actions',
        header: '',
        cell: (c) => (
          <div className="flex justify-end gap-1">
            <Button variant="ghost" size="sm" icon={<Pencil size={14} />} onClick={() => openEdit(c.row.original)} aria-label={t('common.edit')} />
            <Button variant="ghost" size="sm" icon={<Trash2 size={14} className="text-red-500" />} onClick={() => setToDelete(c.row.original)} aria-label={t('common.delete')} />
          </div>
        ),
      }),
    ],
    [t],
  )

  return (
    <div>
      <PageHeader
        title={t('waf.title')}
        description={t('waf.desc')}
        actions={<Button icon={<Plus size={16} />} onClick={openCreate}>{t('waf.new')}</Button>}
      />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <Card>
            <StateView loading={loading} error={error} data={data} onRetry={refetch}>
              {(rows) => <DataTable columns={columns} data={rows} searchPlaceholder={t('waf.search')} emptyMessage={t('waf.empty')} />}
            </StateView>
          </Card>
        </div>

        <Card>
          <CardHeader title={t('waf.recentBlocks')} description={t('waf.recentBlocksDesc')} />
          <CardBody className="p-0">
            {events.data ? (
              <div className="divide-y divide-slate-100 dark:divide-slate-800">
                {events.data.map((e) => (
                  <div key={e.id} className="px-5 py-3">
                    <div className="flex items-center justify-between gap-2">
                      <Badge tone={wafActionTone(e.action)} dot>{t(`enum.wafAction.${e.action}`)}</Badge>
                      <span className="text-xs text-slate-400">{timeAgo(e.time)}</span>
                    </div>
                    <p className="mt-1.5 text-sm font-medium text-slate-700 dark:text-slate-200">{e.rule}</p>
                    <p className="truncate font-mono text-xs text-slate-500 dark:text-slate-400">{e.client_ip} → {e.path}</p>
                  </div>
                ))}
              </div>
            ) : (
              <Spinner />
            )}
          </CardBody>
        </Card>
      </div>

      {/* Create / edit modal */}
      <Modal
        open={formOpen}
        onClose={() => setFormOpen(false)}
        title={form.id ? t('waf.editTitle') : t('waf.newTitle')}
        size="lg"
        footer={
          <>
            <Button variant="secondary" onClick={() => setFormOpen(false)}>{t('common.cancel')}</Button>
            <Button onClick={save} loading={saving}>{form.id ? t('common.saveChanges') : t('waf.createBtn')}</Button>
          </>
        }
      >
        <div className="grid grid-cols-2 gap-4">
          <Field label={t('waf.field.name')} className="col-span-2">
            <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Block SQLi patterns" />
          </Field>
          <Field label={t('waf.field.description')} className="col-span-2">
            <Textarea rows={2} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} placeholder={t('waf.descPlaceholder')} />
          </Field>
          <Field label={t('waf.field.match')}>
            <Select value={form.match_type} onChange={(e) => setForm({ ...form, match_type: e.target.value as WafMatchType })}>
              {MATCH_TYPES.map((m) => (
                <option key={m} value={m}>{t(`enum.matchType.${m}`)}</option>
              ))}
            </Select>
          </Field>
          <Field label={t('waf.field.action')}>
            <Select value={form.action} onChange={(e) => setForm({ ...form, action: e.target.value as WafAction })}>
              {ACTIONS.map((a) => (
                <option key={a} value={a}>{t(`enum.wafAction.${a}`)}</option>
              ))}
            </Select>
          </Field>
          <Field label={t('waf.field.pattern')} className="col-span-2">
            <Input value={form.pattern} onChange={(e) => setForm({ ...form, pattern: e.target.value })} placeholder="(?i)(union.+select|or 1=1)" className="font-mono text-xs" />
          </Field>
          <Field label={t('waf.field.priority')} hint={t('waf.priorityHint')}>
            <Input type="number" value={form.priority} onChange={(e) => setForm({ ...form, priority: Number(e.target.value) })} />
          </Field>
          <div className="flex items-end pb-1">
            <label className="flex items-center gap-2.5 text-sm text-slate-700 dark:text-slate-200">
              <Toggle checked={form.enabled} onChange={(v) => setForm({ ...form, enabled: v })} aria-label="Enabled" /> {t('common.enabled')}
            </label>
          </div>
        </div>
      </Modal>

      <ConfirmDialog
        open={!!toDelete}
        onClose={() => setToDelete(null)}
        onConfirm={remove}
        title={t('waf.deleteTitle')}
        confirmLabel={t('common.delete')}
        message={t('waf.deleteMsg', { name: toDelete?.name ?? '' })}
      />
    </div>
  )
}
