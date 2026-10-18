import { useMemo, type ReactNode } from 'react'
import { clickableRow, ROW_FOCUS } from '@/components/ui/clickableRow'
import { ChevronRight } from 'lucide-react'
import { useVirtualRows } from '@/hooks/useVirtualRows'
import { cn } from '@/lib/cn'
import { StatusBadge } from '@/platform/findings/StatusBadge'
import { ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'
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

const CHECK: ColumnDef = { key: 'check', label: 'Отметка', width: 32, resizable: false }
const SEVERITY: ColumnDef = { key: 'severity', label: 'Severity', width: 112 }
const TAIL: ColumnDef[] = [
  { key: 'status', label: 'Статус', width: 176 },
  { key: 'age', label: 'Возраст', width: 80 },
  { key: 'open', label: '', width: 32, resizable: false },
]

/**
 * Таблица находок: галочки массовой смены, Severity, колонки модуля, статус,
 * возраст. Модуль задаёт свои колонки (`columns`, одна из них — `flex`) и ячейки
 * к ним в том же порядке; границы колонок перетаскиваются, ширины хранятся под
 * `storageKey` — у каждого модуля свой, AD и KSC помнят ширины порознь.
 */
export function CollectorFindingsTable<F extends FindingBase>({ items, selectedIndex, onSelectIndex, onOpen, onReachEnd, checked, onCheck, onCheckAll, storageKey, columns, cells }: FindingsTableProps<F> & {
  storageKey: string
  /** Колонки модуля между Severity и статусом; константа модуля. */
  columns: readonly ColumnDef[]
  cells: (f: F) => ReactNode
}) {
  const { parentRef, rows, totalSize } = useVirtualRows(items.length, ROW_HEIGHT, selectedIndex, onReachEnd)
  const allChecked = items.length > 0 && items.every((f) => checked?.has(f.key))
  const withCheck = !!onCheck
  const all = useMemo(() => [...(withCheck ? [CHECK] : []), SEVERITY, ...columns, ...TAIL], [withCheck, columns])
  const cols = useColumnWidths(storageKey, all)

  return (
    <div ref={parentRef} data-col-resize-root className="h-full overflow-auto">
      <div className="sticky top-0 z-10 grid items-stretch border-b border-grid bg-surface text-[11px] tracking-wide text-text-secondary uppercase" style={cols.gridStyle}>
        <ResizableHeader cols={cols} as="div" className="px-2 py-2" content={{ check: <input type="checkbox" aria-label="Отметить все загруженные" checked={allChecked} onChange={(e) => onCheckAll?.(e.target.checked)} /> }} />
      </div>
      <div style={{ height: totalSize, position: 'relative' }}>
        {rows.map((v) => {
          const f = items[v.index]
          const selected = v.index === selectedIndex
          return (
            <div key={`${f.id}-${f.key}`} {...clickableRow(() => { onSelectIndex(v.index); onOpen(v.index) })} className={cn(ROW_FOCUS, 'absolute top-0 left-0 grid w-full cursor-pointer items-center border-b border-grid text-xs', selected ? 'bg-row-selected' : 'hover:bg-row-hover')} style={{ ...cols.gridStyle, height: ROW_HEIGHT, transform: `translateY(${v.start}px)` }}>
              {onCheck && (
                // Галочка не открывает карточку: клик и клавиши до строки не доходят.
                <div className="px-2" onClick={(e) => e.stopPropagation()} onKeyDown={(e) => e.stopPropagation()}>
                  <input type="checkbox" aria-label="Отметить" checked={checked?.has(f.key) ?? false} onChange={() => undefined}
                    onClick={(e) => onCheck(v.index, e.shiftKey)} />
                </div>
              )}
              <div className="min-w-0 px-2"><SeverityBadge severity={f.severity} /></div>
              {cells(f)}
              <div className="flex min-w-0 items-center gap-1 overflow-hidden px-2">
                <StatusBadge status={f.status} />
                {f.overdue && <span className="text-[11px] text-kind-1" title={`срок ${f.due_date ?? ''}`}>просрочена</span>}
                {f.allowlisted && <span className="text-[11px] text-text-secondary">allow</span>}
              </div>
              <div className="min-w-0 truncate px-2 font-mono tabular-nums text-text-secondary">
                {f.delta === 'new' && <span className="mr-1 text-risk-high" title="появилась в этом снапшоте">+</span>}
                {age(f.age_days)}
              </div>
              <div className="flex justify-end pr-2"><ChevronRight size={14} className="shrink-0 text-text-secondary/40" aria-hidden /></div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
