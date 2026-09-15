import { CheckCircle2, CircleDashed, ListFilter, Sparkles } from 'lucide-react'
import { cn } from '@/lib/cn'
import { tint } from '@/lib/tint'

/**
 * Четыре состояния разметки ATT&CK — не оттенки одного состояния, а четыре
 * разные вещи, поэтому у каждого своя иконка и своё слово, а не только цвет:
 * подтверждено человеком, предложено моделью, закрыто частично (правило
 * ограничено табличным списком — детектирование настолько полно, насколько
 * полон список) и не размечено вовсе.
 */
export type AttackDisplayState = 'confirmed' | 'suggested' | 'partial' | 'unmapped'

const META: Record<AttackDisplayState, { icon: typeof CheckCircle2; color: string; label: string; hint: string }> = {
  confirmed: {
    icon: CheckCircle2,
    color: 'var(--color-attack-confirmed)',
    label: 'Подтверждено человеком',
    hint: 'Разметку проверил и подтвердил аналитик',
  },
  suggested: {
    icon: Sparkles,
    color: 'var(--color-attack-suggested)',
    label: 'Предложено моделью',
    hint: 'Предположение модели, человек ещё не подтвердил',
  },
  partial: {
    icon: ListFilter,
    color: 'var(--color-attack-partial)',
    label: 'Закрыто частично',
    hint: 'Покрывающее правило ограничено табличным списком — детектирование не шире списка',
  },
  unmapped: {
    icon: CircleDashed,
    color: 'var(--color-attack-unmapped)',
    label: 'Не размечено',
    hint: 'Разметка ATT&CK ещё не выполнялась',
  },
}

/** Состояние разметки так, как его отдаёт API: три значения, без «частично». */
export type AttackMarkupStatus = 'unmapped' | 'suggested' | 'confirmed'

export function attackDisplayState(status: AttackMarkupStatus, scoped: boolean): AttackDisplayState {
  if (status === 'unmapped') return 'unmapped'
  if (scoped) return 'partial'
  return status
}

export function AttackStateBadge({
  state,
  className,
}: {
  state: AttackDisplayState
  className?: string
}) {
  const meta = META[state]
  const Icon = meta.icon
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 text-xs font-medium whitespace-nowrap',
        className,
      )}
      style={{ color: meta.color, borderColor: tint(meta.color, 33), backgroundColor: tint(meta.color, 8) }}
      title={meta.hint}
    >
      <Icon size={12} strokeWidth={2.25} aria-hidden />
      {meta.label}
    </span>
  )
}
