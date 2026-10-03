/** Оценка защиты политики; на этапе 1 её нет — «нет оценки», причина во всплывающей подсказке. Подписи оценок — этап 2. */
export function GradeBadge({ grade, reason }: { grade: string | null; reason: string }) {
  if (grade === null) return <span className="text-text-secondary" title={reason}>нет оценки</span>
  return <span className="text-text" title={reason}>{grade}</span>
}
