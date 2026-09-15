import type { Severity } from '@/modules/ad/api/types'
import { SEVERITY_LABELS } from '@/modules/ad/api/types'
import { cn } from '@/lib/cn'

const CLASSES: Record<Severity, string> = {
  Critical: 'border-risk-critical/60 bg-risk-critical/15 text-risk-critical',
  High: 'border-risk-high/60 bg-risk-high/15 text-risk-high',
  Medium: 'border-risk-medium/60 bg-risk-medium/15 text-risk-medium',
  Low: 'border-risk-low/60 bg-risk-low/15 text-risk-low',
  Info: 'border-grid bg-surface text-text-secondary',
}

/** Severity — те же токены цвета, что шкала риска VM; слово всегда рядом. */
export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span className={cn('inline-flex items-center rounded border px-1.5 py-0.5 text-[11px] font-medium whitespace-nowrap', CLASSES[severity], className)}>
      {SEVERITY_LABELS[severity]}
    </span>
  )
}
