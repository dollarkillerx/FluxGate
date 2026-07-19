import { useMemo, useState } from 'react'
import { createColumnHelper } from '@tanstack/react-table'
import { Plus, Pencil, Trash2, X } from 'lucide-react'
import { useRpc } from '@/hooks/useRpc'
import { rpc } from '@/api/rpc'
import { useToast } from '@/context/ToastContext'
import { useI18n } from '@/i18n/I18nContext'
import type { LbStrategy, L4Route } from '@/types'
import { PageHeader } from '@/components/ui/PageHeader'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Modal } from '@/components/ui/Modal'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { Field, Input, Select } from '@/components/ui/Field'
import { Toggle } from '@/components/ui/Toggle'
import { DataTable } from '@/components/ui/DataTable'
import { StateView } from '@/components/ui/States'

const col = createColumnHelper<L4Route>()
const STRATEGIES: LbStrategy[] = ['round_robin', 'least_conn', 'ip_hash', 'weighted']

interface L4Form {
  id?: string
  name: string
  server_names: string[]
  origins: string[]
  strategy: LbStrategy
  connect_timeout_secs: number
  enabled: boolean
}

const emptyForm: L4Form = {
  name: '',
  server_names: [''],
  origins: [''],
  strategy: 'round_robin',
  connect_timeout_secs: 0,
  enabled: true,
}

export function L4RoutesPage() {
  const toast = useToast()
  const { t } = useI18n()
  const { data, loading, error, refetch } = useRpc<L4Route[]>('l4route.list')

  const [formOpen, setFormOpen] = useState(false)
  const [form, setForm] = useState<L4Form>(emptyForm)
  const [saving, setSaving] = useState(false)
  const [toDelete, setToDelete] = useState<L4Route | null>(null)

  const openCreate = () => {
    setForm(emptyForm)
    setFormOpen(true)
  }
  const openEdit = (r: L4Route) => {
    setForm({
      id: r.id,
      name: r.name,
      server_names: r.server_names.length ? [...r.server_names] : [''],
      origins: r.origins.length ? [...r.origins] : [''],
      strategy: r.strategy,
      connect_timeout_secs: r.connect_timeout_secs ?? 0,
      enabled: r.enabled,
    })
    setFormOpen(true)
  }

  // Small string-list editor (SNIs / origins share the shape).
  const setItem = (key: 'server_names' | 'origins', i: number, v: string) =>
    setForm((f) => ({ ...f, [key]: f[key].map((x, idx) => (idx === i ? v : x)) }))
  const addItem = (key: 'server_names' | 'origins') =>
    setForm((f) => ({ ...f, [key]: [...f[key], ''] }))
  const removeItem = (key: 'server_names' | 'origins', i: number) =>
    setForm((f) => ({ ...f, [key]: f[key].filter((_, idx) => idx !== i) }))

  const save = async () => {
    if (!form.name.trim()) {
      toast.warning(t('common.required', { field: t('l4.field.name') }))
      return
    }
    const server_names = form.server_names.map((s) => s.trim()).filter(Boolean)
    const origins = form.origins.map((s) => s.trim()).filter(Boolean)
    if (server_names.length === 0) {
      toast.warning(t('l4.noSni'))
      return
    }
    if (origins.length === 0) {
      toast.warning(t('l4.noOrigins'))
      return
    }
    setSaving(true)
    try {
      const payload = {
        id: form.id,
        name: form.name.trim(),
        server_names,
        origins,
        strategy: form.strategy,
        connect_timeout_secs: Number(form.connect_timeout_secs) || 0,
        enabled: form.enabled,
      }
      await rpc.call(form.id ? 'l4route.update' : 'l4route.create', payload)
      toast.success(form.id ? t('l4.updated') : t('l4.created'), form.name)
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
      await rpc.call('l4route.delete', { id: toDelete.id })
      toast.success(t('l4.deleted'), toDelete.name)
      refetch()
    } catch (e: any) {
      toast.error(t('toast.deleteFailed'), e?.message)
    }
  }

  const columns = useMemo(
    () => [
      col.accessor('name', {
        header: t('l4.col.name'),
        cell: (c) => <span className="font-medium text-slate-800 dark:text-slate-100">{c.getValue()}</span>,
      }),
      col.accessor((r) => r.server_names.join(', '), {
        id: 'sni',
        header: t('l4.col.sni'),
        cell: (c) => <span className="font-mono text-xs text-slate-600 dark:text-slate-300">{c.getValue()}</span>,
      }),
      col.accessor((r) => r.origins.join(', '), {
        id: 'origins',
        header: t('l4.col.origins'),
        cell: (c) => <span className="font-mono text-xs text-slate-600 dark:text-slate-300">{c.getValue()}</span>,
      }),
      col.accessor('strategy', {
        header: t('l4.col.strategy'),
        cell: (c) => <Badge tone="neutral">{t(`enum.strategy.${c.getValue()}`)}</Badge>,
      }),
      col.accessor('enabled', {
        header: t('l4.col.status'),
        cell: (c) => (
          <Badge tone={c.getValue() ? 'success' : 'neutral'} dot>
            {c.getValue() ? t('l4.status.on') : t('l4.status.off')}
          </Badge>
        ),
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

  const listEditor = (key: 'server_names' | 'origins', placeholder: string, addLabel: string) => (
    <div className="space-y-2">
      {form[key].map((v, i) => (
        <div key={i} className="flex items-center gap-2">
          <div className="flex-1">
            <Input value={v} onChange={(e) => setItem(key, i, e.target.value)} placeholder={placeholder} className="font-mono text-xs" />
          </div>
          <Button
            variant="ghost"
            size="sm"
            icon={<X size={14} />}
            onClick={() => removeItem(key, i)}
            disabled={form[key].length === 1}
            aria-label="remove"
            className="shrink-0"
          />
        </div>
      ))}
      <Button variant="secondary" size="sm" icon={<Plus size={14} />} onClick={() => addItem(key)}>
        {addLabel}
      </Button>
    </div>
  )

  return (
    <div>
      <PageHeader
        title={t('l4.title')}
        description={t('l4.desc')}
        actions={<Button icon={<Plus size={16} />} onClick={openCreate}>{t('l4.new')}</Button>}
      />

      <Card>
        <StateView loading={loading} error={error} data={data} onRetry={refetch}>
          {(rows) => <DataTable columns={columns} data={rows} searchPlaceholder={t('l4.search')} emptyMessage={t('l4.empty')} />}
        </StateView>
      </Card>

      <Modal
        open={formOpen}
        onClose={() => setFormOpen(false)}
        title={form.id ? t('l4.editTitle') : t('l4.newTitle')}
        footer={
          <>
            <Button variant="secondary" onClick={() => setFormOpen(false)}>{t('common.cancel')}</Button>
            <Button onClick={save} loading={saving}>{form.id ? t('common.saveChanges') : t('l4.createBtn')}</Button>
          </>
        }
      >
        <div className="space-y-4">
          <Field label={t('l4.field.name')}>
            <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="reality-gw" />
          </Field>
          <Field label={t('l4.field.sni')} hint={t('l4.sniHint')}>
            {listEditor('server_names', t('l4.sniPlaceholder'), t('l4.addSni'))}
          </Field>
          <Field label={t('l4.field.origins')} hint={t('l4.originsHint')}>
            {listEditor('origins', t('l4.originPlaceholder'), t('l4.addOrigin'))}
          </Field>
          <Field label={t('l4.field.strategy')}>
            <Select value={form.strategy} onChange={(e) => setForm({ ...form, strategy: e.target.value as LbStrategy })}>
              {STRATEGIES.map((s) => (
                <option key={s} value={s}>{t(`enum.strategy.${s}`)}</option>
              ))}
            </Select>
          </Field>
          <Field label={t('l4.field.timeout')}>
            <Input
              type="number"
              min={0}
              value={form.connect_timeout_secs}
              onChange={(e) => setForm({ ...form, connect_timeout_secs: Number(e.target.value) })}
              className="tabular-nums"
            />
          </Field>
          <label className="flex items-center gap-2.5 text-sm text-slate-700 dark:text-slate-200">
            <Toggle checked={form.enabled} onChange={(v) => setForm({ ...form, enabled: v })} aria-label={t('l4.enabled')} />
            <span>{t('l4.enabled')}</span>
          </label>
        </div>
      </Modal>

      <ConfirmDialog
        open={!!toDelete}
        onClose={() => setToDelete(null)}
        onConfirm={remove}
        title={t('l4.deleteTitle')}
        confirmLabel={t('common.delete')}
        message={t('l4.deleteMsg', { name: toDelete?.name ?? '' })}
      />
    </div>
  )
}
