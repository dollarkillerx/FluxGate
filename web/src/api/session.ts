// Bearer-token session storage.
//
// The token is kept in localStorage and mirrored in a module variable so the
// RPC client can read it synchronously on every call without React context.

const TOKEN_KEY = 'fluxgate.token'
const USER_KEY = 'fluxgate.user'

let token: string | null = localStorage.getItem(TOKEN_KEY)

export function getToken(): string | null {
  return token
}

export function getUser(): string | null {
  return localStorage.getItem(USER_KEY)
}

export function setSession(t: string, user: string): void {
  token = t
  localStorage.setItem(TOKEN_KEY, t)
  localStorage.setItem(USER_KEY, user)
}

export function clearSession(): void {
  token = null
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(USER_KEY)
}

/** Broadcast that the server rejected our token, so the app can log out. */
export function notifyUnauthorized(): void {
  window.dispatchEvent(new Event('fluxgate:unauthorized'))
}

interface LoginResult {
  token: string
  username: string
}

/**
 * Exchange credentials for a token via the `auth.login` JSON-RPC method.
 *
 * This deliberately uses a direct `fetch` (not the shared rpc client) to avoid
 * an import cycle and the client's 401-logout side effects during login.
 */
export async function login(username: string, password: string): Promise<LoginResult> {
  let res: Response
  try {
    res = await fetch('/rpc', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'auth.login', params: { username, password } }),
    })
  } catch {
    // Backend unreachable. In dev, accept the documented demo credentials so
    // the console is usable against the in-repo mock backend.
    if (import.meta.env.DEV && username === 'admin' && password === 'admin') {
      return { token: 'mock-dev-token', username }
    }
    // Throw a translation key; the Login page resolves it via t().
    throw new Error('login.unreachable')
  }

  const body = await res.json().catch(() => null)
  if (body?.error) throw new Error('login.invalid')
  if (!body?.result?.token) throw new Error('login.failed')
  return body.result as LoginResult
}
