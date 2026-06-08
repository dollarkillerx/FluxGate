import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { createColumnHelper } from '@tanstack/react-table'
import { Plus, Upload, RefreshCw, Trash2, ShieldCheck, Info } from 'lucide-react'
import { useRpc } from '@/hooks/useRpc'
import { rpc } from '@/api/rpc'
import { useToast } from '@/context/ToastContext'
import { useI18n } from '@/i18n/I18nContext'
import type { TlsCertificate, Settings } from '@/types'
import type { Translate } from '@/i18n/I18nContext'
import { PageHeader } from '@/components/ui/PageHeader'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Toggle } from '@/components/ui/Toggle'
import { Modal } from '@/components/ui/Modal'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { Field, Input, Textarea } from '@/components/ui/Field'
import { DataTable } from '@/components/ui/DataTable'
import { StateView } from '@/components/ui/States'
import { formatDate, daysUntil } from '@/lib/utils'
import { certTone } from '@/lib/status'

const col = createColumnHelper<TlsCertificate>()

function expiryLabel(cert: TlsCertificate, t: Translate): string {
  const d = daysUntil(cert.expires_at)
  if (cert.status === 'pending') return t('certs.issuing')
  if (d < 0) return t('certs.expiredAgo', { n: -d })
  return t('certs.inDays', { n: d })
}

export function CertificatesPage() {
  const toast = useToast()
  const { t } = useI18n()
  // Poll so a Pending ACME cert flips to Valid automatically once the
  // background HTTP-01 order completes (issuance takes ~10-60s).
  const { data, loading, error, refetch } = useRpc<TlsCertificate[]>('tls.cert.list', {}, [], 5000)
  // Drives the request dialog's hint: ACME on → Let's Encrypt; off → self-signed.
  const { data: settings } = useRpc<Settings>('settings.get')
  const acmeOn = !!(settings?.acme.enabled && settings?.acme.agree_tos)

  const [requestOpen, setRequestOpen] = useState(false)
  const [uploadOpen, setUploadOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [reqDomain, setReqDomain] = useState('')
  const [upload, setUpload] = useState({ domain: '', issuer: '', cert: '', key: '' })
  const [toRenew, setToRenew] = useState<TlsCertificate | null>(null)
  const [toDelete, setToDelete] = useState<TlsCertificate | null>(null)
  // Optimistic auto-renew overrides by cert id. The spec has no dedicated
  // "update certificate" RPC, so we reflect the switch locally rather than
  // calling tls.cert.upload (which would insert a duplicate certificate).
  const [autoRenewOverride, setAutoRenewOverride] = useState<Record<string, boolean>>({})

  const rows = useMemo(
    () => (data ?? []).map((c) => (c.id in autoRenewOverride ? { ...c, auto_renew: autoRenewOverride[c.id] } : c)),
    [data, autoRenewOverride],
  )

  const requestCert = async () => {
    if (!reqDomain.trim()) {
      toast.warning(t('certs.domainRequired'))
      return
    }
    setBusy(true)
    try {
      await rpc.call('tls.cert.request', { domain: reqDomain.trim() })
      toast.success(
        t('certs.requested'),
        t(acmeOn ? 'certs.requestedAcme' : 'certs.requestedSelf', { domain: reqDomain }),
      )
      setRequestOpen(false)
      setReqDomain('')
      refetch()
    } catch (e: any) {
      toast.error(t('toast.requestFailed'), e?.message)
    } finally {
      setBusy(false)
    }
  }

  const uploadCert = async () => {
    if (!upload.cert.trim()) {
      toast.warning(t('certs.certRequired'))
      return
    }
    setBusy(true)
    try {
      // The backend parses the real PEM; domain is optional (derived from cert).
      const res = await rpc.call<{ domain: string }>('tls.cert.upload', {
        domain: upload.domain.trim() || undefined,
        cert_pem: upload.cert,
        key_pem: upload.key || undefined,
      })
      toast.success(t('certs.uploaded'), res.domain)
      setUploadOpen(false)
      setUpload({ domain: '', issuer: '', cert: '', key: '' })
      refetch()
    } catch (e: any) {
      toast.error(t('toast.uploadFailed'), e?.message)
    } finally {
      setBusy(false)
    }
  }

  const renew = async () => {
    if (!toRenew) return
    try {
      await rpc.call('tls.cert.renew', { id: toRenew.id })
      toast.success(t('certs.renewed'), toRenew.domain)
      refetch()
    } catch (e: any) {
      toast.error(t('toast.renewFailed'), e?.message)
    }
  }

  const remove = async () => {
    if (!toDelete) return
    try {
      await rpc.call('tls.cert.delete', { id: toDelete.id })
      toast.success(t('certs.deleted'), toDelete.domain)
      refetch()
    } catch (e: any) {
      toast.error(t('toast.deleteFailed'), e?.message)
    }
  }

  const toggleAuto = (cert: TlsCertificate, next: boolean) => {
    // Optimistic only — wire to a real `tls.cert.update` method when available.
    setAutoRenewOverride((o) => ({ ...o, [cert.id]: next }))
    toast.success(next ? t('certs.autoOn') : t('certs.autoOff'), cert.domain)
  }

  const columns = useMemo(
    () => [
      col.accessor('domain', {
        header: t('certs.col.domain'),
        cell: (c) => <span className="font-medium text-slate-800 dark:text-slate-100">{c.getValue()}</span>,
      }),
      col.accessor('issuer', {
        header: t('certs.col.issuer'),
        cell: (c) => <span className="text-slate-600 dark:text-slate-300">{c.getValue()}</span>,
      }),
      col.accessor('expires_at', {
        header: t('certs.col.expires'),
        cell: (c) => {
          const cert = c.row.original
          const danger = cert.status === 'expired'
          const warn = cert.status === 'expiring'
          return (
            <div>
              <div className="text-slate-700 dark:text-slate-200">{formatDate(c.getValue())}</div>
              <div className={danger ? 'text-xs text-red-500' : warn ? 'text-xs text-amber-500' : 'text-xs text-slate-400'}>{expiryLabel(cert, t)}</div>
            </div>
          )
        },
      }),
      col.accessor('auto_renew', {
        header: t('certs.col.autoRenew'),
        cell: (c) => <Toggle checked={c.getValue()} onChange={(v) => toggleAuto(c.row.original, v)} aria-label="Toggle auto-renew" />,
      }),
      col.accessor('status', {
        header: t('certs.col.status'),
        cell: (c) => <Badge tone={certTone(c.getValue())} dot>{t(`enum.certStatus.${c.getValue()}`)}</Badge>,
      }),
      col.display({
        id: 'actions',
        header: '',
        cell: (c) => (
          <div className="flex justify-end gap-1">
            <Button variant="ghost" size="sm" icon={<RefreshCw size={14} />} onClick={() => setToRenew(c.row.original)} aria-label={t('certs.request')} />
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
        title={t('certs.title')}
        description={t('certs.desc')}
        actions={
          <>
            <Button variant="secondary" icon={<Upload size={16} />} onClick={() => setUploadOpen(true)}>{t('certs.upload')}</Button>
            <Button icon={<Plus size={16} />} onClick={() => setRequestOpen(true)}>{t('certs.request')}</Button>
          </>
        }
      />

      <Card>
        <StateView loading={loading} error={error} data={data} onRetry={refetch}>
          {() => <DataTable columns={columns} data={rows} searchPlaceholder={t('certs.search')} emptyMessage={t('certs.empty')} />}
        </StateView>
      </Card>

      {/* Request modal */}
      <Modal
        open={requestOpen}
        onClose={() => setRequestOpen(false)}
        title={t('certs.requestTitle')}
        description={t('certs.requestDesc')}
        footer={
          <>
            <Button variant="secondary" onClick={() => setRequestOpen(false)}>{t('common.cancel')}</Button>
            <Button onClick={requestCert} loading={busy}>{t('certs.request')}</Button>
          </>
        }
      >
        {acmeOn ? (
          <div className="mb-4 flex items-start gap-2 rounded-md border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-700 dark:border-emerald-500/30 dark:bg-emerald-500/10 dark:text-emerald-300">
            <ShieldCheck size={16} className="mt-0.5 shrink-0" />
            <span>{t('certs.acmeOnHint')}</span>
          </div>
        ) : (
          <div className="mb-4 flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-700 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-300">
            <Info size={16} className="mt-0.5 shrink-0" />
            <span>
              {t('certs.acmeOffHint')}{' '}
              <Link to="/settings" className="font-medium underline underline-offset-2 hover:text-amber-900 dark:hover:text-amber-200">
                {t('certs.acmeOffCta')}
              </Link>
            </span>
          </div>
        )}
        <Field label={t('certs.field.domain')} hint={t('certs.domainHint')}>
          <Input value={reqDomain} onChange={(e) => setReqDomain(e.target.value)} placeholder="app.example.com" />
        </Field>
      </Modal>

      {/* Upload modal */}
      <Modal
        open={uploadOpen}
        onClose={() => setUploadOpen(false)}
        title={t('certs.uploadTitle')}
        size="lg"
        footer={
          <>
            <Button variant="secondary" onClick={() => setUploadOpen(false)}>{t('common.cancel')}</Button>
            <Button onClick={uploadCert} loading={busy}>{t('certs.upload')}</Button>
          </>
        }
      >
        <div className="space-y-4">
          <Field label={t('certs.field.domain')} hint={t('certs.uploadDomainHint')}>
            <Input value={upload.domain} onChange={(e) => setUpload({ ...upload, domain: e.target.value })} placeholder="app.example.com" />
          </Field>
          <Field label={t('certs.field.certPem')}>
            <Textarea rows={5} value={upload.cert} onChange={(e) => setUpload({ ...upload, cert: e.target.value })} placeholder="-----BEGIN CERTIFICATE-----" className="font-mono text-xs" />
          </Field>
          <Field label={t('certs.field.keyPem')}>
            <Textarea rows={4} value={upload.key} onChange={(e) => setUpload({ ...upload, key: e.target.value })} placeholder="-----BEGIN PRIVATE KEY-----" className="font-mono text-xs" />
          </Field>
        </div>
      </Modal>

      <ConfirmDialog
        open={!!toRenew}
        onClose={() => setToRenew(null)}
        onConfirm={renew}
        tone="primary"
        title={t('certs.renewTitle')}
        confirmLabel={t('certs.renewConfirm')}
        message={t('certs.renewMsg', { domain: toRenew?.domain ?? '' })}
      />

      <ConfirmDialog
        open={!!toDelete}
        onClose={() => setToDelete(null)}
        onConfirm={remove}
        title={t('certs.deleteTitle')}
        confirmLabel={t('common.delete')}
        message={t('certs.deleteMsg', { domain: toDelete?.domain ?? '' })}
      />
    </div>
  )
}
