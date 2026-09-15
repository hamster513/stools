import { CircleDot } from 'lucide-react'
import type { AttackConfidence } from '@/modules/siem/api/types'
import { cn } from '@/lib/cn'

const META: Record<AttackConfidence, { color: string }> = {
  высокая: { color: 'var(--color-confidence-high)' },
  средняя: { color: 'var(--color-confidence-medium)' },
  низкая: { color: 'var(--color-confidence-low)' },
}

/**
 * Уверенность разметки — качественная, не числовая (число создавало ложную
 * точность на живом прогоне). Цвет не единственный носитель смысла — слово
 * всегда рядом.
 */
export function ConfidenceBadge({ confidence, className }: { confidence: AttackConfidence; className?: string }) {
  const meta = META[confidence]
  return (
    <span
      className={cn('inline-flex items-center gap-1 text-xs whitespace-nowrap', className)}
      style={{ color: meta.color }}
    >
      <CircleDot size={10} strokeWidth={2.5} aria-hidden />
      уверенность: {confidence}
    </span>
  )
}
