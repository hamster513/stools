import { AlertTriangle, CircleAlert, FileWarning, Minus } from 'lucide-react'
import type { FindingSeverity, ParseStatus } from '@/modules/siem/api/types'
import { cn } from '@/lib/cn'

/**
 * Маркировка правила в инвентаре: на что оператору смотреть в первую
 * очередь. Уровней четыре, и они не оттенки одного, а разные поводы,
 * поэтому у каждого своя иконка и своё слово — цвет никогда не единственный
 * носитель смысла.
 *
 * «Не разобрано» стоит выше любых находок намеренно: у неразобранного
 * правила находок нет вовсе, и без отдельной пометки оно выглядело бы
 * чистым. Тихо чистое правило хуже шумного.
 */
export type AttentionLevel = 'unparsed' | 'high' | 'medium' | 'clean'

const META: Record<
  AttentionLevel,
  { icon: typeof AlertTriangle; color: string; label: string; hint: string }
> = {
  unparsed: {
    icon: FileWarning,
    color: 'var(--color-kind-2)',
    label: 'Не разобрано',
    hint: 'Тело правила не разобрано — находок по нему нет не потому, что их нет',
  },
  high: {
    icon: AlertTriangle,
    color: 'var(--color-kind-1)',
    label: 'Разобрать',
    hint: 'Есть открытые находки высокой тяжести',
  },
  medium: {
    icon: CircleAlert,
    color: 'var(--color-kind-3)',
    label: 'Посмотреть',
    hint: 'Есть открытые находки средней и меньшей тяжести',
  },
  clean: {
    icon: Minus,
    color: 'var(--color-text-secondary)',
    label: 'Чисто',
    hint: 'Открытых находок нет',
  },
}

export function attentionLevel(
  parseStatus: ParseStatus,
  openFindings: number,
  maxSeverity: FindingSeverity | null,
): AttentionLevel {
  if (parseStatus !== 'ok') return 'unparsed'
  if (openFindings === 0) return 'clean'
  return maxSeverity === 'high' ? 'high' : 'medium'
}

export function AttentionBadge({
  level,
  count,
  className,
}: {
  level: AttentionLevel
  count: number
  className?: string
}) {
  const meta = META[level]
  const Icon = meta.icon
  return (
    <span
      className={cn('inline-flex items-center gap-1.5 text-xs whitespace-nowrap', className)}
      style={{ color: meta.color }}
      title={meta.hint}
    >
      <Icon size={13} strokeWidth={2.25} aria-hidden />
      {meta.label}
      {count > 0 && <span className="font-mono tabular-nums opacity-80">{count}</span>}
    </span>
  )
}
