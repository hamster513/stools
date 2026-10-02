import { STATUS_TITLES, type FindingStatus } from './types'
import { cn } from '@/lib/cn'

/** Открытые заметнее закрытых: решения людей приглушены, переоткрытая — цветом тревоги. */
const CLASSES: Record<FindingStatus, string> = {
  new: 'border-border text-text',
  in_work: 'border-primary/60 bg-primary/15 text-text',
  risk_accepted: 'border-grid text-text-secondary',
  false_positive: 'border-grid text-text-secondary',
  fixed: 'border-kind-accepted/60 bg-kind-accepted/10 text-kind-accepted',
  resolved: 'border-kind-accepted/30 text-kind-accepted/70',
  reopened: 'border-kind-1/60 bg-kind-1/10 text-kind-1',
}

export function StatusBadge({ status, className }: { status: FindingStatus; className?: string }) {
  return (
    <span className={cn('inline-flex items-center rounded border px-1.5 py-0.5 text-[11px] font-medium whitespace-nowrap', CLASSES[status], className)}>
      {STATUS_TITLES[status]}
    </span>
  )
}
