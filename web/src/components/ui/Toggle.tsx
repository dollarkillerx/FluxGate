import { cn } from '@/lib/utils'

interface ToggleProps {
  checked: boolean
  onChange: (value: boolean) => void
  disabled?: boolean
  'aria-label'?: string
  size?: 'sm' | 'md'
}

/** Fluent-style switch. */
export function Toggle({ checked, onChange, disabled, size = 'md', ...rest }: ToggleProps) {
  const track = size === 'sm' ? 'h-[18px] w-8' : 'h-5 w-10'
  const knob = size === 'sm' ? 'h-3.5 w-3.5' : 'h-4 w-4'
  const onShift = size === 'sm' ? 'translate-x-3.5' : 'translate-x-5'
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={rest['aria-label']}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cn(
        'focus-ring relative inline-flex shrink-0 items-center rounded-full transition-colors disabled:cursor-not-allowed disabled:opacity-50',
        track,
        checked ? 'bg-brand-600' : 'bg-slate-300 dark:bg-slate-600',
      )}
    >
      <span
        className={cn(
          'inline-block transform rounded-full bg-white shadow transition-transform',
          knob,
          checked ? onShift : 'translate-x-0.5',
        )}
      />
    </button>
  )
}
