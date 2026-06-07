// JSON-RPC 2.0 client.
//
// Every backend interaction goes through `rpc.call<T>(method, params)`. The
// client talks to `POST /rpc`. When the backend is unreachable (e.g. running
// `npm run dev` without the Rust server) or `VITE_USE_MOCK=true`, it
// transparently falls back to the in-repo mock so the UI stays demoable.

import { mockCall } from '@/mock'
import { RpcError } from './errors'
import { getToken, clearSession, notifyUnauthorized } from './session'

export { RpcError }

interface RpcResponse<T> {
  jsonrpc: string
  id: number | string | null
  result?: T
  error?: { code: number; message: string }
}

const ALWAYS_MOCK = import.meta.env.VITE_USE_MOCK === 'true'

let nextId = 0

function authHeaders(): Record<string, string> {
  // Prefer the logged-in session token; fall back to a build-time token.
  const token = getToken() ?? import.meta.env.VITE_ADMIN_TOKEN
  return token ? { Authorization: `Bearer ${token}` } : {}
}

async function rpcCall<T>(method: string, params: unknown = {}): Promise<T> {
  if (ALWAYS_MOCK) {
    return mockCall<T>(method, params)
  }

  let res: Response
  try {
    res = await fetch('/rpc', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ jsonrpc: '2.0', id: ++nextId, method, params }),
    })
  } catch {
    // Network failure — backend not running. Fall back to mock in dev so the
    // console remains usable; rethrow in production builds.
    if (import.meta.env.DEV) return mockCall<T>(method, params)
    throw new RpcError(-32603, 'Network error: admin server unreachable')
  }

  let body: RpcResponse<T>
  try {
    body = (await res.json()) as RpcResponse<T>
  } catch {
    throw new RpcError(-32700, `Malformed response (HTTP ${res.status})`)
  }

  if (body.error) {
    // -32001 = unauthorized. The token is bad/expired — drop the session and
    // bounce to the login screen. (auth.login uses a direct fetch, so a failed
    // login never reaches this path.)
    if (body.error.code === -32001) {
      clearSession()
      notifyUnauthorized()
    }
    throw new RpcError(body.error.code, body.error.message)
  }
  if (body.result === undefined) {
    throw new RpcError(-32603, 'Empty RPC result')
  }
  return body.result
}

export const rpc = {
  call: rpcCall,
}
