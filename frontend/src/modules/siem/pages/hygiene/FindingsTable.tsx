import { useEffect, useRef } from 'react'
import { clickableRow, ROW_FOCUS } from '@/components/ui/clickableRow'
import { useVirtualizer } from '@tanstack/react-virtual'
import { CheckCircle2, ChevronRight, XCircle } from 'lucide-react'
import type { FindingListItem } from '@/modules/siem/api/types'
import { OBJECT_TYPE_LABELS, POLARITY_LABELS } from '@/modules/siem/api/types'
import { KindBadge } from '@/modules/siem/components/ui/KindBadge'
import { StatusBadge } from '@/modules/siem/components/ui/StatusBadge'
import { cn } from '@/lib/cn'

const ROW_HEIGHT = 32

interface FindingsTableProps {
  items: FindingListItem[]
  offset: number
  /** Вызывается, когда прокрутка подошла к концу загруженного —
   *  страница догружает следующую порцию. */
  onReachEnd?: () => void
  selectedIndex: number
  onSelectIndex: (index: number) => void
  onOpen: (index: number) => void
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
}: FindingsTableProps) {
  const parentRef = useRef<HTMLDivElement>(null)

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
    <div ref={parentRef} className="h-full overflow-auto">
      {/* Минимальная ширина: при узкой области колонка объекта иначе
          схлопывается до одной буквы. Прокрутка горизонтальная — внутри
          таблицы, у страницы её быть не должно. */}
      <div className="sticky top-0 z-10 flex min-w-[980px] border-b border-grid bg-surface text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
        <div className="w-12 shrink-0 px-2 py-2 text-right">№</div>
        <div className="w-40 shrink-0 px-2 py-2">Класс</div>
        <div className="min-w-0 flex-1 px-2 py-2">Объект</div>
        <div className="w-44 shrink-0 px-2 py-2">Поле</div>
        <div className="w-24 shrink-0 px-2 py-2">Полярность</div>
        <div className="w-20 shrink-0 px-2 py-2">В списке</div>
        <div className="w-32 shrink-0 px-2 py-2">Статус</div>
      </div>

      <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
        {virtualRows.map((virtualRow) => {
          const item = items[virtualRow.index]
          const isSelected = virtualRow.index === selectedIndex
          return (
            <div
              key={item.id}
              data-index={virtualRow.index}
              {...clickableRow(() => {
                onSelectIndex(virtualRow.index)
                onOpen(virtualRow.index)
              })}
              className={cn(
                ROW_FOCUS,
                'absolute top-0 left-0 flex w-full min-w-[980px] cursor-pointer items-center border-b border-grid text-xs',
                isSelected ? 'bg-row-selected' : 'hover:bg-row-hover',
              )}
              style={{ height: ROW_HEIGHT, transform: `translateY(${virtualRow.start}px)` }}
            >
              <div className="w-12 shrink-0 px-2 text-right font-mono tabular-nums text-text-secondary">
                {offset + virtualRow.index + 1}
              </div>
              <div className="w-40 shrink-0 px-2">
                <KindBadge kind={item.kind} />
              </div>
              <div className="min-w-0 flex-1 truncate px-2 font-mono text-text" title={item.object_name}>
                {item.object_name}
                <span className="ml-1.5 text-[10px] text-text-secondary">{OBJECT_TYPE_LABELS[item.object_type]}</span>
              </div>
              <div className="w-44 shrink-0 truncate px-2 font-mono text-text-secondary" title={item.field}>
                {item.field}
              </div>
              <div className="w-24 shrink-0 px-2 text-text-secondary">{POLARITY_LABELS[item.polarity]}</div>
              <div className="w-20 shrink-0 px-2">
                {item.in_table ? (
                  <CheckCircle2 size={14} className="text-kind-accepted" aria-label="есть в списке" />
                ) : (
                  <XCircle size={14} className="text-text-secondary/50" aria-label="нет в списке" />
                )}
              </div>
              <div className="flex w-32 shrink-0 items-center gap-1.5 px-2">
                <StatusBadge status={item.status} />
              </div>
              <ChevronRight size={14} className="ml-auto mr-2 shrink-0 text-text-secondary/40" aria-hidden />
            </div>
          )
        })}
      </div>
    </div>
  )
}
