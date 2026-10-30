import type { ImageItem, TrivySeverity } from '@/modules/vm/api/types'
import { TRIVY_SEVERITIES, TRIVY_SEVERITY_LABELS } from '@/modules/vm/api/types'
import { cn } from '@/lib/cn'

/** Цвет оценки Trivy: общий для счётчиков и бейджа. */
const DOT: Record<TrivySeverity, string> = {
  critical: 'text-risk-critical',
  high: 'text-risk-high',
  medium: 'text-risk-medium',
  low: 'text-risk-low',
  unknown: 'text-text-secondary',
}

/**
 * Находки образа по оценке Trivy: пять счётчиков от критических к неизвестным.
 * Цвет точки — не единственный носитель смысла: порядок постоянный, оценки — в подсказке.
 */
export function TrivyCounts({ trivy, className }: { trivy: ImageItem['trivy']; className?: string }) {
  const text = `Оценка Trivy — ${TRIVY_SEVERITIES.map((s) => `${TRIVY_SEVERITY_LABELS[s]}: ${trivy[s]}`).join(', ')}`
  return (
    <span role="img" aria-label={text} title={text} className={cn('inline-flex items-center gap-2.5 font-mono text-xs tabular-nums', className)}>
      {TRIVY_SEVERITIES.map((s) => (
        <span key={s} className={cn('inline-flex items-center gap-1', trivy[s] === 0 ? 'text-text-secondary/60' : 'text-text')}>
          <span className={cn('inline-block h-2 w-2 rounded-full bg-current', DOT[s], trivy[s] === 0 && 'opacity-40')} aria-hidden />
          {trivy[s]}
        </span>
      ))}
    </span>
  )
}

/** Оценка Trivy словом: цвет не единственный носитель смысла. */
export function TrivyBadge({ severity }: { severity: TrivySeverity }) {
  return <span className={cn('text-xs font-medium', DOT[severity])}>{TRIVY_SEVERITY_LABELS[severity]}</span>
}
