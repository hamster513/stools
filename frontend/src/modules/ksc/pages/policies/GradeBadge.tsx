import { GRADE_LABELS, type PolicyGrade } from '@/modules/ksc/api/types'
import { cn } from '@/lib/cn'

/** Цвета оценки — токены шкалы риска: «плохая» — high, «нормальная» — medium, «хорошая» — как принятое. */
const CLASSES: Record<PolicyGrade, string> = {
  bad: 'border-risk-high/60 bg-risk-high/15 text-risk-high',
  ok: 'border-risk-medium/60 bg-risk-medium/15 text-risk-medium',
  good: 'border-kind-accepted/60 bg-kind-accepted/10 text-kind-accepted',
}

/** Оценка защиты политики; без оценки — «нет оценки». Причина — во всплывающей подсказке. `large` — крупно, для вкладки «Оценка». */
export function GradeBadge({ grade, reason, large = false }: { grade: PolicyGrade | null; reason: string; large?: boolean }) {
  if (grade === null) return <span className={cn('text-text-secondary', large && 'text-base font-semibold')} title={reason}>нет оценки</span>
  return (
    <span
      className={cn('inline-flex items-center rounded border font-medium whitespace-nowrap', large ? 'px-2.5 py-1 text-base' : 'px-1.5 py-0.5 text-[11px]', CLASSES[grade])}
      title={reason}
    >
      {GRADE_LABELS[grade]}
    </span>
  )
}
