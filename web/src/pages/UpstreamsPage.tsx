import { useMemo, useState } from 'react'
import { createColumnHelper } from '@tanstack/react-table'
import { Plus, Pencil, Trash2, Eye, X } from 'lucide-react'
import { useRpc } from '@/hooks/useRpc'
import { rpc } from '@/api/rpc'
import { useToast } from '@/context/ToastContext'
import { useI18n } from '@/i18n/I18nContext'
import type { LbStrategy, Upstream, UpstreamServer } from '@/types'
import { PageHeader } from '@/components/ui/PageHeader'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Modal } from '@/components/ui/Modal'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { Field, Input, Select } from '@/components/ui/Field'
import { DataTable } from '@/components/ui/DataTable'
import { StateView } from '@/components/ui/States'
import { upstreamTone } from '@/lib/status'

const col = createColumnHelper<Upstream>()

const STRATEGIES: LbStrategy[] = ['round_robin', 'least_conn', 'ip_hash', 'weighted']

interface ServerRow {
  address: string
  weight: number
}

interface UpstreamForm {
  id?: string
  name: string
  strategy: LbStrategy
  servers: ServerRow[]
}

const blankRow = (): ServerRow => ({ address: '', weight: 1 })
const emptyForm: UpstreamForm = { name: '', strategy: 'round_robin', servers: [blankRow()] }

export function UpstreamsPage() {
  const toast = useToast()
  const { t } = useI18n()
  const { data, loading, error, refetch } = useRpc<Upstream[]>('upstream.list')

  const [detail, setDetail] = useState<Upstream | null>(null)
  const [formOpen, setFormOpen] = useState(false)
  const [form, setForm] = useState<UpstreamForm>(emptyForm)
  const [saving, setSaving] = useState(false)
  const [toDelete, setToDelete] = useState<Upstream | null>(null)

  const openCreate = () => {
    setForm(emptyForm)
    setFormOpen(true)
  }
  const openEdit = (u: Upstream) => {
    setForm({
      id: u.id,
      name: u.name,
      strategy: u.strategy,
      servers: u.servers.length ? u.servers.map((s) => ({ address: s.address, weight: s.weight })) : [blankRow()],
    })
    setFormOpen(true)
  }

  const setServer = (i: number, patch: Partial<ServerRow>) =>
    setForm((f) => ({ ...f, servers: f.servers.map((s, idx) => (idx === i ? { ...s, ...patch } : s)) }))
  const addServer = () => setForm((f) => ({ ...f, servers: [...f.servers, blankRow()] }))
  const removeServer = (i: number) =>
    setForm((f) => ({ ...f, servers: f.servers.filter((_, idx) => idx !== i) }))

  const save = async () => {
    if (!form.name.trim()) {
      toast.warning(t('common.required', { field: t('upstreams.field.name') }))
      return
    }
    // Collapse to non-empty addresses; weight falls back to 1.
    const rows = form.servers
      .map((s) => ({ address: s.address.trim(), weight: Number(s.weight) || 1 }))
      .filter((s) => s.address)
    if (rows.length === 0) {
      toast.warning(t('upstreams.noServers'))
      return
    }
    setSaving(true)
    try {
      // Preserve known health/latency for addresses that already existed so an
      // unrelated edit (e.g. rename) doesn't mark every node healthy again.
      // (The server re-probes on save anyway, but this keeps the optimistic state sane.)
      const existing = new Map((data?.find((u) => u.id === form.id)?.servers ?? []).map((s) => [s.address, s]))
      const servers: UpstreamServer[] = rows.map((s) => {
        const prev = existing.get(s.address)
        return prev
          ? { ...s, healthy: prev.healthy, latency_ms: prev.latency_ms }
          : { ...s, healthy: true, latency_ms: 0 }
      })
      const payload = { id: form.id, name: form.name, strategy: form.strategy, servers }
      await rpc.call(form.id ? 'upstream.update' : 'upstream.create', payload)
      toast.success(form.id ? t('upstreams.updated') : t('upstreams.created'), form.name)
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
      await rpc.call('upstream.delete', { id: toDelete.id })
      toast.success(t('upstreams.deleted'), toDelete.name)
      refetch()
    } catch (e: any) {
      toast.error(t('toast.deleteFailed'), e?.message)
    }
  }

  const columns = useMemo(
    () => [
      col.accessor('name', {
        header: t('upstreams.col.name'),
        cell: (c) => <span className="font-medium text-slate-800 dark:text-slate-100">{c.getValue()}</span>,
      }),
      col.accessor('strategy', {
        header: t('upstreams.col.strategy'),
        cell: (c) => <Badge tone="neutral">{t(`enum.strategy.${c.getValue()}`)}</Badge>,
      }),
      col.accessor((u) => u.servers.length, {
        id: 'nodes',
        header: t('upstreams.col.nodes'),
        cell: (c) => <span className="tabular-nums">{c.getValue()}</span>,
      }),
      col.accessor('healthy_servers', {
        header: t('upstreams.col.healthy'),
        cell: (c) => (
          <span className="tabular-nums">
            <span className={c.getValue() === c.row.original.servers.length ? 'text-emerald-600' : 'text-amber-600'}>{c.getValue()}</span>
            <span className="text-slate-400"> / {c.row.original.servers.length}</span>
          </span>
        ),
      }),
      col.accessor('status', {
        header: t('upstreams.col.status'),
        cell: (c) => <Badge tone={upstreamTone(c.getValue())} dot>{t(`enum.upstreamStatus.${c.getValue()}`)}</Badge>,
      }),
      col.display({
        id: 'actions',
        header: '',
        cell: (c) => (
          <div className="flex justify-end gap-1">
            <Button variant="ghost" size="sm" icon={<Eye size={14} />} onClick={() => setDetail(c.row.original)} aria-label={t('upstreams.viewNodes')} />
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
        title={t('upstreams.title')}
        description={t('upstreams.desc')}
        actions={<Button icon={<Plus size={16} />} onClick={openCreate}>{t('upstreams.new')}</Button>}
      />

      <Card>
        <StateView loading={loading} error={error} data={data} onRetry={refetch}>
          {(rows) => <DataTable columns={columns} data={rows} searchPlaceholder={t('upstreams.search')} emptyMessage={t('upstreams.empty')} />}
        </StateView>
      </Card>

      {/* Node detail modal */}
      <Modal
        open={!!detail}
        onClose={() => setDetail(null)}
        title={detail ? t('upstreams.nodesTitle', { name: detail.name }) : ''}
        size="lg"
        description={detail ? t('upstreams.nodesMeta', { strategy: t(`enum.strategy.${detail.strategy}`), healthy: detail.healthy_servers, total: detail.servers.length }) : ''}
      >
        {detail && (
          <div className="overflow-hidden rounded-md border border-slate-200 dark:border-slate-700">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-left text-xs uppercase text-slate-500 dark:border-slate-700 dark:bg-slate-800/50">
                  <th className="px-4 py-2 font-semibold">{t('upstreams.node.address')}</th>
                  <th className="px-4 py-2 font-semibold">{t('upstreams.node.weight')}</th>
                  <th className="px-4 py-2 font-semibold">{t('upstreams.node.latency')}</th>
                  <th className="px-4 py-2 font-semibold">{t('upstreams.node.health')}</th>
                </tr>
              </thead>
              <tbody>
                {detail.servers.map((s) => (
                  <tr key={s.address} className="border-b border-slate-100 last:border-0 dark:border-slate-800">
                    <td className="px-4 py-2.5 font-mono text-xs">{s.address}</td>
                    <td className="px-4 py-2.5 tabular-nums">{s.weight}</td>
                    <td className="px-4 py-2.5 tabular-nums">{s.healthy ? `${s.latency_ms} ms` : '—'}</td>
                    <td className="px-4 py-2.5">
                      <Badge tone={s.healthy ? 'success' : 'danger'} dot>{s.healthy ? t('upstreams.node.healthy') : t('upstreams.node.down')}</Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Modal>

      {/* Create / edit modal */}
      <Modal
        open={formOpen}
        onClose={() => setFormOpen(false)}
        title={form.id ? t('upstreams.editTitle') : t('upstreams.newTitle')}
        footer={
          <>
            <Button variant="secondary" onClick={() => setFormOpen(false)}>{t('common.cancel')}</Button>
            <Button onClick={save} loading={saving}>{form.id ? t('common.saveChanges') : t('upstreams.createBtn')}</Button>
          </>
        }
      >
        <div className="space-y-4">
          <Field label={t('upstreams.field.name')}>
            <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="api-cluster" />
          </Field>
          <Field label={t('upstreams.field.strategy')}>
            <Select value={form.strategy} onChange={(e) => setForm({ ...form, strategy: e.target.value as LbStrategy })}>
              {STRATEGIES.map((s) => (
                <option key={s} value={s}>{t(`enum.strategy.${s}`)}</option>
              ))}
            </Select>
          </Field>
          <Field label={t('upstreams.field.servers')} hint={t('upstreams.serversHint')}>
            <div className="space-y-2">
              <div className="flex items-center gap-2 px-0.5 text-[11px] font-medium uppercase tracking-wide text-slate-400 dark:text-slate-500">
                <span className="flex-1">{t('upstreams.node.address')}</span>
                <span className="w-20 shrink-0">{t('upstreams.node.weight')}</span>
                <span className="w-8 shrink-0" />
              </div>
              {form.servers.map((s, i) => (
                <div key={i} className="flex items-center gap-2">
                  {/* Wrap inputs so their width is set on the container, not fought
                      against the Input's own `w-full` base class. */}
                  <div className="flex-1">
                    <Input
                      value={s.address}
                      onChange={(e) => setServer(i, { address: e.target.value })}
                      placeholder={t('upstreams.addrPlaceholder')}
                      className="font-mono text-xs"
                    />
                  </div>
                  <div className="w-20 shrink-0">
                    <Input
                      type="number"
                      min={1}
                      value={s.weight}
                      onChange={(e) => setServer(i, { weight: Number(e.target.value) })}
                      aria-label={t('upstreams.weightPlaceholder')}
                      className="tabular-nums"
                    />
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    icon={<X size={14} />}
                    onClick={() => removeServer(i)}
                    disabled={form.servers.length === 1}
                    aria-label={t('upstreams.removeServer')}
                    className="shrink-0"
                  />
                </div>
              ))}
              <Button variant="secondary" size="sm" icon={<Plus size={14} />} onClick={addServer}>
                {t('upstreams.addServer')}
              </Button>
            </div>
          </Field>
        </div>
      </Modal>

      <ConfirmDialog
        open={!!toDelete}
        onClose={() => setToDelete(null)}
        onConfirm={remove}
        title={t('upstreams.deleteTitle')}
        confirmLabel={t('common.delete')}
        message={t('upstreams.deleteMsg', { name: toDelete?.name ?? '' })}
      />
    </div>
  )
}
