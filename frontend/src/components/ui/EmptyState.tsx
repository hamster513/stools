import type { ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'

interface EmptyStateProps {
  icon: LucideIcon
  title: string
  description: string
  action?: ReactNode
}

/** Пустые состояния объясняют, что делать дальше, а не просто пустуют. */
export function EmptyState({ icon: Icon, title, description, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded border border-dashed border-grid px-6 py-16 text-center">
      <Icon size={28} strokeWidth={1.5} className="text-text-secondary" aria-hidden />
      <div className="text-sm font-medium text-text">{title}</div>
      <p className="max-w-md text-sm text-text-secondary">{description}</p>
      {action}
    </div>
  )
}
