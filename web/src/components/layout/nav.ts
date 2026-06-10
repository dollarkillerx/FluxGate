import {
  LayoutDashboard,
  Route as RouteIcon,
  Server,
  ShieldCheck,
  ShieldAlert,
  Ban,
  Lock,
  ScrollText,
  Activity,
  Settings as SettingsIcon,
  type LucideIcon,
} from 'lucide-react'

export interface NavItem {
  to: string
  /** i18n key for the nav label. */
  labelKey: string
  icon: LucideIcon
}

export const NAV_ITEMS: NavItem[] = [
  { to: '/', labelKey: 'nav.dashboard', icon: LayoutDashboard },
  { to: '/routes', labelKey: 'nav.routes', icon: RouteIcon },
  { to: '/upstreams', labelKey: 'nav.upstreams', icon: Server },
  { to: '/waf', labelKey: 'nav.waf', icon: ShieldCheck },
  { to: '/risk', labelKey: 'nav.risk', icon: ShieldAlert },
  { to: '/access', labelKey: 'nav.access', icon: Ban },
  { to: '/certificates', labelKey: 'nav.certificates', icon: Lock },
  { to: '/logs', labelKey: 'nav.logs', icon: ScrollText },
  { to: '/metrics', labelKey: 'nav.metrics', icon: Activity },
  { to: '/settings', labelKey: 'nav.settings', icon: SettingsIcon },
]
