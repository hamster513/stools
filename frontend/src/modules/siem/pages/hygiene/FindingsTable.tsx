import { useEffect, useRef } from 'react'
import { clickableRow, ROW_FOCUS } from '@/components/ui/clickableRow'
import { useVirtualizer } from '@tanstack/react-virtual'
import { CheckCircle2, ChevronRight, XCircle } from 'lucide-react'
import type { FindingListItem } from '@/modules/siem/api/types'
import { OBJECT_TYPE_LABELS, POLARITY_LABELS } from '@/modules/siem/api/types'
import { KindBadge } from '@/modules/siem/components/ui/KindBadge'
import { StatusBadge } from '@/platform/findings/StatusBadge'
import { cn } from '@/lib/cn'
import { ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'

const ROW_HEIGHT = 32

// Ширина «Объекта» — минимум: при узкой области колонка иначе схлопывается до
// одной буквы. Прокрутка горизонтальная — внутри таблицы, у страницы её быть не должно.
const COLUMNS: ColumnDef[] = [
  { key: 'n', label: '№', width: 48, align: 'right' },
  { key: 'kind', label: 'Класс', width: 160 },
  { key: 'object', label: 'Объект', width: 260, flex: true },
  { key: 'field', label: 'Поле', width: 176 },
  { key: 'polarity', label: 'Полярность', width: 96 },
  { key: 'in_table', label: 'В списке', width: 80 },
  { key: 'status', label: 'Статус', width: 176 },
  { key: 'age', label: 'Возраст', width: 80 },
  { key: 'open', label: '', width: 32, resizable: false },
]
const WITH_CHECK: ColumnDef[] = [{ key: 'check', label: 'Отметка', width: 32, resizable: false }, ...COLUMNS]

interface FindingsTableProps {
  items: FindingListItem[]
  offset: number
  /** Вызывается, когда прокрутка подошла к концу загруженного —
   *  страница догружает следующую порцию. */
  onReachEnd?: () => void
  selectedIndex: number
  onSelectIndex: (index: number) => void
  onOpen: (index: number) => void
  /** Отмеченные для массовой смены ключи; без onCheck галочек нет (аудитор). */
  checked?: ReadonlySet<string>
  /** Отметить строку; shift — диапазон от прошлой отмеченной. */
  onCheck?: (index: number, shift: boolean) => void
  onCheckAll?: (on: boolean) => void
}

function age(days: number | null): string {
  return days === null ? '—' : `${days} дн.`
}

/**
 * Строки, отличающиеся только скрытым значением, всё равно должны быть
 * различимы — колонка «№» даёт непрозрачный порядковый номер в пределах
 * текущей выдачи вместо хеша значения (хеш восстанавливается словарём).
 */
export function FindingsTable({
  items,
  offset,
  selectedIndex,
  onSelectIndex,
  onOpen,
  onReachEnd,
  checked,
  onCheck,
  onCheckAll,
}: FindingsTableProps) {
  const parentRef = useRef<HTMLDivElement>(null)
  const allChecked = items.length > 0 && items.every((f) => checked?.has(f.key))
  const cols = useColumnWidths('siem-hygiene-findings-columns', onCheck ? WITH_CHECK : COLUMNS)

  const virtualizer = useVirtualizer({
    count: items.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 12,
  })

  useEffect(() => {
    if (selectedIndex >= 0 && selectedIndex < items.length) {
      virtualizer.scrollToIndex(selectedIndex, { align: 'auto' })
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedIndex])

  // Догрузка по приближению к концу загруженного: реагируем на последнюю
  // отрисованную строку, а не на событие прокрутки — виртуализатор уже
  // знает, докуда доехали, и лишний обработчик scroll не нужен.
  const virtualRows = virtualizer.getVirtualItems()
  const lastVisible = virtualRows.length ? virtualRows[virtualRows.length - 1].index : 0
  useEffect(() => {
    if (onReachEnd && items.length > 0 && lastVisible >= items.length - 20) {
      onReachEnd()
    }
  }, [lastVisible, items.length, onReachEnd])

  return (
    <div ref={parentRef} data-col-resize-root className="h-full overflow-auto">
      <div className="sticky top-0 z-10 grid items-center border-b border-grid bg-surface text-[11px] tracking-wide text-text-secondary uppercase" style={cols.gridStyle}>
        <ResizableHeader cols={cols} as="div" className="px-2 py-2" content={{ check: <input type="checkbox" aria-label="Отметить все загруженные" checked={allChecked} onChange={(e) => onCheckAll?.(e.target.checked)} /> }} />
      </div>

      <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
        {virtualRows.map((virtualRow) => {
          const item = items[virtualRow.index]
          const isSelected = virtualRow.index === selectedIndex
          return (
            <div
              key={`${item.id}-${item.key}`}
              data-index={virtualRow.index}
              {...clickableRow(() => {
                onSelectIndex(virtualRow.index)
                onOpen(virtualRow.index)
              })}
              className={cn(
                ROW_FOCUS,
                'absolute top-0 left-0 grid w-full cursor-pointer items-center border-b border-grid text-xs',
                isSelected ? 'bg-row-selected' : 'hover:bg-row-hover',
              )}
              style={{ ...cols.gridStyle, height: ROW_HEIGHT, transform: `translateY(${virtualRow.start}px)` }}
            >
              {onCheck && (
                // Галочка не открывает карточку: клик и клавиши до строки не доходят.
                <div className="px-2" onClick={(e) => e.stopPropagation()} onKeyDown={(e) => e.stopPropagation()}>
                  <input type="checkbox" aria-label="Отметить" checked={checked?.has(item.key) ?? false} onChange={() => undefined}
                    onClick={(e) => onCheck(virtualRow.index, e.shiftKey)} />
                </div>
              )}
              <div className="min-w-0 px-2 text-right font-mono tabular-nums text-text-secondary">
                {offset + virtualRow.index + 1}
              </div>
              <div className="min-w-0 overflow-hidden px-2">
                <KindBadge kind={item.kind} />
              </div>
              <div className="min-w-0 truncate px-2 font-mono text-text" title={item.object_name}>
                {item.object_name}
                <span className="ml-1.5 text-[10px] text-text-secondary">{OBJECT_TYPE_LABELS[item.object_type]}</span>
              </div>
              <div className="min-w-0 truncate px-2 font-mono text-text-secondary" title={item.field}>
                {item.field}
              </div>
              <div className="min-w-0 truncate px-2 text-text-secondary">{POLARITY_LABELS[item.polarity]}</div>
              <div className="min-w-0 px-2">
                {item.in_table ? (
                  <CheckCircle2 size={14} className="text-kind-accepted" aria-label="есть в списке" />
                ) : (
                  <XCircle size={14} className="text-text-secondary/50" aria-label="нет в списке" />
                )}
              </div>
              <div className="flex min-w-0 items-center gap-1 overflow-hidden px-2">
                <StatusBadge status={item.status} />
                {item.overdue && <span className="text-[11px] text-kind-1" title={`срок ${item.due_date ?? ''}`}>просрочена</span>}
              </div>
              <div className="min-w-0 truncate px-2 font-mono tabular-nums text-text-secondary">{age(item.age_days)}</div>
              <div className="flex justify-end pr-2"><ChevronRight size={14} className="shrink-0 text-text-secondary/40" aria-hidden /></div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
