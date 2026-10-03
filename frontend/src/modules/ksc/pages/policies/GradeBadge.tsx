import type { PolicyGrade } from '@/modules/ksc/api/types'
import { cn } from '@/lib/cn'

const GRADES: Record<PolicyGrade, { label: string; className: string }> = {
  bad: { label: 'плохая', className: 'text-risk-high' },
  ok: { label: 'нормальная', className: 'text-risk-medium' },
  good: { label: 'хорошая', className: 'text-kind-accepted' },
}

/** Оценка защиты политики; на этапе 1 её нет — «нет оценки», причина во всплывающей подсказке. */
export function GradeBadge({ grade, reason }: { grade: PolicyGrade | null; reason: string }) {
  if (grade === null) return <span className="text-text-secondary" title={reason}>нет оценки</span>
  return <span className={cn('font-medium', GRADES[grade].className)} title={reason}>{GRADES[grade].label}</span>
}
