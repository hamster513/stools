import type { ReactNode } from 'react'
import { ChevronDown } from 'lucide-react'
import { cn } from '@/lib/cn'
import { ResizeHandle } from './ResizeHandle'
import type { ColumnDef, ColumnWidths } from './useColumnWidths'

/**
 * Ячейка заголовка списка на сетке с сортировкой по щелчку: подпись-кнопка, ручка ширины и «сбросить» в
 * резиновой колонке, пока ширины изменены. Свой заголовок вместо ResizableHeader: `aria-sort` и сортировка
 * остаются на ячейке. Колонка без `sortKey` — просто подпись. `ascending` — порядок, в котором сортирует
 * `sortKey` (по умолчанию от большего к меньшему): от него зависят `aria-sort` и стрелка.
 */
export function SortableTh<S extends string>({ children, sortKey, sort, onSort, ascending = false, cols, col }: {
  children: ReactNode
  sortKey?: S
  sort: S
  onSort: (sort: S) => void
  ascending?: boolean
  cols: ColumnWidths
  col: ColumnDef
}) {
  const handle = col.resizable !== false && <ResizeHandle cols={cols} col={col.key} label={col.label} />
  const reset = col.flex && cols.customized && (
    <button type="button" onClick={cols.reset} className="mr-2 shrink-0 rounded font-normal tracking-normal text-text-secondary normal-case hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" title="Вернуть ширины колонок по умолчанию">сбросить</button>
  )
  if (!sortKey) return <div className="relative flex min-w-0 items-center"><div className="min-w-0 flex-1 px-2 py-2">{children}</div>{reset}{handle}</div>
  const active = sort === sortKey
  return (
    <div role="columnheader" aria-sort={active ? (ascending ? 'ascending' : 'descending') : 'none'} className="relative flex min-w-0 items-center">
      <button
        type="button"
        onClick={() => onSort(sortKey)}
        className={cn('flex min-w-0 flex-1 items-center gap-1 px-2 py-2 text-left uppercase hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring', active && 'text-text')}
      >
        {children}
        {active && <ChevronDown size={11} className={cn(ascending && 'rotate-180')} aria-hidden />}
      </button>
      {reset}
      {handle}
    </div>
  )
}
