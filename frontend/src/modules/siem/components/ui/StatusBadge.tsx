import { CheckCircle2, CircleDashed, Loader2 } from 'lucide-react'
import type { FindingStatus } from '@/modules/siem/api/types'
import { FINDING_STATUS_LABELS } from '@/modules/siem/api/types'
import { cn } from '@/lib/cn'
import { tint } from '@/lib/tint'

const STATUS_META: Record<FindingStatus, { icon: typeof CircleDashed; color: string }> = {
  open: { icon: CircleDashed, color: 'var(--color-text-secondary)' },
  accepted: { icon: CheckCircle2, color: 'var(--color-kind-accepted)' },
  in_progress: { icon: Loader2, color: 'var(--color-focus-ring)' },
}

export function StatusBadge({ status, className }: { status: FindingStatus; className?: string }) {
  const meta = STATUS_META[status]
  const Icon = meta.icon
  return (
    <span
      className={cn('inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 text-xs whitespace-nowrap', className)}
      style={{ color: meta.color, borderColor: tint(meta.color, 33), backgroundColor: tint(meta.color, 8) }}
    >
      <Icon size={12} strokeWidth={2.25} aria-hidden />
      {FINDING_STATUS_LABELS[status]}
    </span>
  )
}
