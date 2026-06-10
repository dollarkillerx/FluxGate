import { Navigate, Route, Routes } from 'react-router-dom'
import { useAuth } from '@/context/AuthContext'
import { Login } from '@/pages/Login'
import { AppLayout } from '@/components/layout/AppLayout'
import { Dashboard } from '@/pages/Dashboard'
import { RoutesPage } from '@/pages/RoutesPage'
import { RouteAnalyticsPage } from '@/pages/RouteAnalyticsPage'
import { UpstreamsPage } from '@/pages/UpstreamsPage'
import { WafRulesPage } from '@/pages/WafRulesPage'
import { RiskPage } from '@/pages/RiskPage'
import { AccessPage } from '@/pages/AccessPage'
import { CertificatesPage } from '@/pages/CertificatesPage'
import { AccessLogsPage } from '@/pages/AccessLogsPage'
import { MetricsPage } from '@/pages/MetricsPage'
import { SettingsPage } from '@/pages/SettingsPage'

export default function App() {
  const { token } = useAuth()

  // Unauthenticated → only the login screen is reachable.
  if (!token) return <Login />

  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route path="/" element={<Dashboard />} />
        <Route path="/routes" element={<RoutesPage />} />
        <Route path="/routes/analytics" element={<RouteAnalyticsPage />} />
        <Route path="/upstreams" element={<UpstreamsPage />} />
        <Route path="/waf" element={<WafRulesPage />} />
        <Route path="/risk" element={<RiskPage />} />
        <Route path="/access" element={<AccessPage />} />
        <Route path="/certificates" element={<CertificatesPage />} />
        <Route path="/logs" element={<AccessLogsPage />} />
        <Route path="/metrics" element={<MetricsPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  )
}
