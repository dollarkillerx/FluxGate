import type { CertStatus, StatusTone, UpstreamStatus, WafAction } from '@/types'

export function upstreamTone(s: UpstreamStatus): StatusTone {
  return s === 'healthy' ? 'success' : s === 'degraded' ? 'warning' : 'danger'
}

export function certTone(s: CertStatus): StatusTone {
  switch (s) {
    case 'valid':
      return 'success'
    case 'expiring':
      return 'warning'
    case 'expired':
      return 'danger'
    case 'pending':
      return 'info'
  }
}

export function wafActionTone(a: WafAction): StatusTone {
  return a === 'allow' ? 'success' : a === 'deny' ? 'danger' : 'warning'
}

export function httpStatusTone(code: number): StatusTone {
  if (code < 300) return 'success'
  if (code < 400) return 'info'
  if (code < 500) return 'warning'
  return 'danger'
}
