import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { useTheme } from '@/context/ThemeContext'

const COLORS = {
  brand: '#2563eb',
  red: '#dc2626',
  emerald: '#059669',
  amber: '#d97706',
  violet: '#7c3aed',
}

type ColorKey = keyof typeof COLORS

function useAxis() {
  const { theme } = useTheme()
  const grid = theme === 'dark' ? '#1e293b' : '#eef2f7'
  const text = theme === 'dark' ? '#94a3b8' : '#94a3b8'
  return { grid, text }
}

interface SeriesDef {
  key: string
  label: string
  color: ColorKey
}

interface TrendChartProps {
  data: Array<Record<string, any>>
  xKey: string
  series: SeriesDef[]
  height?: number
  area?: boolean
  /** Format Y-axis tick values. */
  yFormatter?: (v: number) => string
}

/** Multi-series line/area chart used across Dashboard & Metrics. */
export function TrendChart({ data, xKey, series, height = 240, area = true, yFormatter }: TrendChartProps) {
  const { grid, text } = useAxis()

  const tooltipStyle = {
    fontSize: 12,
    borderRadius: 8,
    border: '1px solid var(--tw-tooltip-border, #e2e8f0)',
  }

  if (area) {
    return (
      <ResponsiveContainer width="100%" height={height}>
        <AreaChart data={data} margin={{ top: 8, right: 8, left: -8, bottom: 0 }}>
          <defs>
            {series.map((s) => (
              <linearGradient key={s.key} id={`grad-${s.key}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={COLORS[s.color]} stopOpacity={0.28} />
                <stop offset="100%" stopColor={COLORS[s.color]} stopOpacity={0.02} />
              </linearGradient>
            ))}
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke={grid} vertical={false} />
          <XAxis dataKey={xKey} tick={{ fontSize: 11, fill: text }} tickLine={false} axisLine={{ stroke: grid }} minTickGap={24} />
          <YAxis tick={{ fontSize: 11, fill: text }} tickLine={false} axisLine={false} width={48} tickFormatter={yFormatter} />
          <Tooltip contentStyle={tooltipStyle} />
          {series.map((s) => (
            <Area
              key={s.key}
              type="monotone"
              dataKey={s.key}
              name={s.label}
              stroke={COLORS[s.color]}
              strokeWidth={2}
              fill={`url(#grad-${s.key})`}
              dot={false}
              isAnimationActive={false}
            />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    )
  }

  return (
    <ResponsiveContainer width="100%" height={height}>
      <LineChart data={data} margin={{ top: 8, right: 8, left: -8, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke={grid} vertical={false} />
        <XAxis dataKey={xKey} tick={{ fontSize: 11, fill: text }} tickLine={false} axisLine={{ stroke: grid }} minTickGap={24} />
        <YAxis tick={{ fontSize: 11, fill: text }} tickLine={false} axisLine={false} width={48} tickFormatter={yFormatter} />
        <Tooltip contentStyle={tooltipStyle} />
        {series.map((s) => (
          <Line key={s.key} type="monotone" dataKey={s.key} name={s.label} stroke={COLORS[s.color]} strokeWidth={2} dot={false} isAnimationActive={false} />
        ))}
      </LineChart>
    </ResponsiveContainer>
  )
}

interface SparklineProps {
  data: Array<{ value: number }>
  color?: ColorKey
  height?: number
}

/** Compact sparkline for metric cards. */
export function Sparkline({ data, color = 'brand', height = 48 }: SparklineProps) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 2, right: 0, left: 0, bottom: 0 }}>
        <defs>
          <linearGradient id={`spark-${color}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={COLORS[color]} stopOpacity={0.3} />
            <stop offset="100%" stopColor={COLORS[color]} stopOpacity={0} />
          </linearGradient>
        </defs>
        <Area type="monotone" dataKey="value" stroke={COLORS[color]} strokeWidth={1.8} fill={`url(#spark-${color})`} dot={false} isAnimationActive={false} />
      </AreaChart>
    </ResponsiveContainer>
  )
}
