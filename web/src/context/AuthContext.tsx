import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { clearSession, getToken, getUser, login as apiLogin, setSession } from '@/api/session'

interface AuthCtx {
  token: string | null
  user: string | null
  login: (username: string, password: string) => Promise<void>
  logout: () => void
}

const Ctx = createContext<AuthCtx | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(() => getToken())
  const [user, setUser] = useState<string | null>(() => getUser())

  // The RPC client clears the session and fires this event on a 401.
  useEffect(() => {
    const onUnauthorized = () => {
      setToken(null)
      setUser(null)
    }
    window.addEventListener('fluxgate:unauthorized', onUnauthorized)
    return () => window.removeEventListener('fluxgate:unauthorized', onUnauthorized)
  }, [])

  const login = async (username: string, password: string) => {
    const result = await apiLogin(username, password)
    setSession(result.token, result.username)
    setToken(result.token)
    setUser(result.username)
  }

  const logout = () => {
    clearSession()
    setToken(null)
    setUser(null)
  }

  return <Ctx.Provider value={{ token, user, login, logout }}>{children}</Ctx.Provider>
}

export function useAuth() {
  const ctx = useContext(Ctx)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
