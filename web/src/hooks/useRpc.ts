import { useCallback, useEffect, useState } from 'react'
import { rpc, RpcError } from '@/api/rpc'

interface RpcState<T> {
  data: T | null
  loading: boolean
  error: string | null
  /** Re-run the query. */
  refetch: () => void
}

/**
 * Declarative data fetch for a JSON-RPC method. Re-runs whenever a value in
 * `deps` changes. Exposes loading/error/data so pages can render all states.
 *
 * Pass `pollMs` to auto-refresh on an interval. Polling is silent — `data` is
 * kept across refreshes, so charts/tables update in place without a spinner.
 */
export function useRpc<T>(
  method: string,
  params: unknown = {},
  deps: unknown[] = [],
  pollMs?: number,
): RpcState<T> {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [tick, setTick] = useState(0)

  const refetch = useCallback(() => setTick((t) => t + 1), [])

  // Background polling: bump the tick on an interval to re-run the fetch effect.
  useEffect(() => {
    if (!pollMs) return
    const id = setInterval(refetch, pollMs)
    return () => clearInterval(id)
  }, [pollMs, refetch])

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    rpc
      .call<T>(method, params)
      .then((res) => {
        if (!cancelled) setData(res)
      })
      .catch((e: unknown) => {
        if (!cancelled) {
          const msg = e instanceof RpcError ? `${e.message} (code ${e.code})` : String(e)
          setError(msg)
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [method, tick, ...deps])

  return { data, loading, error, refetch }
}
