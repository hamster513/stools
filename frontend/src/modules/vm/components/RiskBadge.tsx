import type { RiskLevel } from '@/modules/vm/api/types'
import { LEVEL_LABELS } from '@/modules/vm/api/types'
import { cn } from '@/lib/cn'

const COLOR: Record<RiskLevel, string> = {
  low: 'var(--color-risk-low)',
  medium: 'var(--color-risk-medium)',
  high: 'var(--color-risk-high)',
  critical: 'var(--color-risk-critical)',
}

export const LEVEL_TEXT: Record<RiskLevel, string> = {
  low: 'text-risk-low',
  medium: 'text-risk-medium',
  high: 'text-risk-high',
  critical: 'text-risk-critical',
}

/** Риск — число, полоса и слово: цвет никогда не единственный носитель смысла. */
export function RiskBadge({ score, level, compact }: { score: number; level: RiskLevel; compact?: boolean }) {
  return (
    <span className="inline-flex items-center gap-2" title={`${score} — ${LEVEL_LABELS[level]}`}>
      <span className={cn('w-7 text-right font-mono text-xs tabular-nums', LEVEL_TEXT[level])}>{score}</span>
      <span className="h-1.5 w-14 overflow-hidden rounded-full bg-grid" aria-hidden>
        <span className="block h-full rounded-full" style={{ width: `${score}%`, backgroundColor: COLOR[level] }} />
      </span>
      {!compact && <span className="text-[11px] text-text-secondary">{LEVEL_LABELS[level]}</span>}
    </span>
  )
}
