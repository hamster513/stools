import { Filter, X } from 'lucide-react'
import { cn } from '@/lib/cn'

/**
 * Правило платформы для каждого списка с фильтрами: панель фильтров скрыта
 * по умолчанию и открывается этой кнопкой в шапке рядом с заголовком и
 * поиском; при закрытой панели выбранные фильтры видны чипами, и каждый чип
 * снимает ровно свой фильтр. Состояние панели — useFiltersPanel.
 */
export interface FilterChip {
  label: string
  clear: () => void
}

export function FiltersButton({ open, onToggle, count }: { open: boolean; onToggle: () => void; count: number }) {
  return (
    <button type="button" onClick={onToggle} aria-expanded={open} className={cn('flex items-center gap-1.5 rounded border px-2 py-1 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring', open ? 'border-border bg-row-selected text-text' : 'border-border text-text-secondary hover:bg-row-hover hover:text-text')}>
      <Filter size={13} aria-hidden /> Фильтры{count > 0 && <span className="font-mono tabular-nums text-text">{count}</span>}
    </button>
  )
}

/** Строка чипов на всю ширину шапки: шапка должна быть `flex-wrap`. */
export function FilterChips({ chips }: { chips: FilterChip[] }) {
  if (chips.length === 0) return null
  return (
    <div className="flex basis-full flex-wrap gap-1.5">
      {chips.map((c) => (
        <button key={c.label} type="button" onClick={c.clear} title="Снять фильтр" className="flex items-center gap-1 rounded border border-border px-1.5 py-0.5 text-[11px] text-text hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">
          {c.label} <X size={11} className="text-text-secondary" aria-hidden />
        </button>
      ))}
    </div>
  )
}
