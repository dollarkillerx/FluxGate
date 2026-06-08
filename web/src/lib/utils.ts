/** Tiny classnames joiner (no clsx dependency needed). */
export function cn(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(' ')
}

/** Compact large numbers: 48201774 -> "48.2M". */
export function formatNumber(n: number): string {
  if (n < 1000) return String(n)
  if (n < 1_000_000) return `${(n / 1000).toFixed(n < 10_000 ? 1 : 0)}K`
  if (n < 1_000_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  return `${(n / 1_000_000_000).toFixed(2)}B`
}

/** Full grouped number: 48201774 -> "48,201,774". */
export function formatFull(n: number): string {
  return n.toLocaleString('en-US')
}

/** ISO timestamp -> "Jun 7, 14:32:08". */
export function formatTime(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
}

/** ISO timestamp -> "Jun 7, 2026". */
export function formatDate(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
}

/** Relative "time ago" string. */
export function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  const days = Math.floor(hrs / 24)
  return `${days}d ago`
}

/** Days until an ISO timestamp (negative if past). */
export function daysUntil(iso: string): number {
  return Math.round((new Date(iso).getTime() - Date.now()) / 86_400_000)
}

/** Humanize a snake_case enum value: "round_robin" -> "Round Robin". */
export function humanize(s: string): string {
  return s
    .split('_')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ')
}

/** Seconds -> "4d 7h 32m". */
export function formatUptime(secs: number): string {
  const d = Math.floor(secs / 86400)
  const h = Math.floor((secs % 86400) / 3600)
  const m = Math.floor((secs % 3600) / 60)
  return [d && `${d}d`, h && `${h}h`, `${m}m`].filter(Boolean).join(' ')
}

/** ISO alpha-2 country code → flag emoji (regional indicators); 🌐 for unknown. */
export function flag(cc: string): string {
  if (!/^[A-Za-z]{2}$/.test(cc)) return '🌐'
  return String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65))
}

/** Country code → localized country name (via Intl), or `unknown` for "??". */
export function countryLabel(cc: string, locale: string, unknown: string): string {
  if (cc === '??' || !/^[A-Za-z]{2}$/.test(cc)) return unknown
  try {
    return new Intl.DisplayNames([locale], { type: 'region' }).of(cc.toUpperCase()) ?? cc
  } catch {
    return cc
  }
}
