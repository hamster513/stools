import type { ReactNode } from 'react'
import { clickableRow, ROW_FOCUS } from '@/components/ui/clickableRow'
import { ChevronRight } from 'lucide-react'
import { useVirtualRows } from '@/hooks/useVirtualRows'
import { cn } from '@/lib/cn'
import { StatusBadge } from '@/platform/findings/StatusBadge'
import { SeverityBadge } from './SeverityBadge'
import type { FindingBase } from './types'

const ROW_HEIGHT = 32

export interface FindingsTableProps<F extends FindingBase> {
  items: F[]
  selectedIndex: number
  onSelectIndex: (i: number) => void
  onOpen: (i: number) => void
  onReachEnd?: () => void
  /** Отмеченные для массовой смены ключи; без onCheck галочек нет (аудитор). */
  checked?: ReadonlySet<string>
  /** Отметить строку; shift — диапазон от прошлой отмеченной. */
  onCheck?: (i: number, shift: boolean) => void
  onCheckAll?: (on: boolean) => void
}

function age(days: number | null): string {
  return days === null ? '—' : `${days} дн.`
}

/**
 * Таблица находок: галочки массовой смены, Severity, колонки модуля, статус,
 * возраст. Модуль задаёт ширину таблицы (класс min-w-[…]), заголовки и ячейки
 * своих колонок.
 */
export function CollectorFindingsTable<F extends FindingBase>({ items, selectedIndex, onSelectIndex, onOpen, onReachEnd, checked, onCheck, onCheckAll, minWidth, head, cells }: FindingsTableProps<F> & {
  minWidth: string
  head: ReactNode
  cells: (f: F) => ReactNode
}) {
  const { parentRef, rows, totalSize } = useVirtualRows(items.length, ROW_HEIGHT, selectedIndex, onReachEnd)
  const allChecked = items.length > 0 && items.every((f) => checked?.has(f.key))

  return (
    <div ref={parentRef} className="h-full overflow-auto">
      <div className={`sticky top-0 z-10 flex ${minWidth} items-center border-b border-grid bg-surface text-[11px] font-semibold tracking-wide text-text-secondary uppercase`}>
        {onCheck && <div className="w-8 shrink-0 pl-3"><input type="checkbox" aria-label="Отметить все загруженные" checked={allChecked} onChange={(e) => onCheckAll?.(e.target.checked)} /></div>}
        <div className="w-28 shrink-0 px-2 py-2">Severity</div>
        {head}
        <div className="w-44 shrink-0 px-2 py-2">Статус</div>
        <div className="w-20 shrink-0 px-2 py-2">Возраст</div>
      </div>
      <div style={{ height: totalSize, position: 'relative' }}>
        {rows.map((v) => {
          const f = items[v.index]
          const selected = v.index === selectedIndex
          return (
            <div key={`${f.id}-${f.key}`} {...clickableRow(() => { onSelectIndex(v.index); onOpen(v.index) })} className={cn(ROW_FOCUS, `absolute top-0 left-0 flex w-full ${minWidth} cursor-pointer items-center border-b border-grid text-xs`, selected ? 'bg-row-selected' : 'hover:bg-row-hover')} style={{ height: ROW_HEIGHT, transform: `translateY(${v.start}px)` }}>
              {onCheck && (
                // Галочка не открывает карточку: клик и клавиши до строки не доходят.
                <div className="w-8 shrink-0 pl-3" onClick={(e) => e.stopPropagation()} onKeyDown={(e) => e.stopPropagation()}>
                  <input type="checkbox" aria-label="Отметить" checked={checked?.has(f.key) ?? false} onChange={() => undefined}
                    onClick={(e) => onCheck(v.index, e.shiftKey)} />
                </div>
              )}
              <div className="w-28 shrink-0 px-2"><SeverityBadge severity={f.severity} /></div>
              {cells(f)}
              <div className="flex w-44 shrink-0 items-center gap-1 px-2">
                <StatusBadge status={f.status} />
                {f.overdue && <span className="text-[11px] text-kind-1" title={`срок ${f.due_date ?? ''}`}>просрочена</span>}
                {f.allowlisted && <span className="text-[11px] text-text-secondary">allow</span>}
              </div>
              <div className="w-20 shrink-0 px-2 font-mono tabular-nums text-text-secondary">
                {f.delta === 'new' && <span className="mr-1 text-risk-high" title="появилась в этом снапшоте">+</span>}
                {age(f.age_days)}
              </div>
              <ChevronRight size={14} className="mr-2 ml-auto shrink-0 text-text-secondary/40" aria-hidden />
            </div>
          )
        })}
      </div>
    </div>
  )
}
