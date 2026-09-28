import type { ReactNode } from 'react'
import { clickableRow, ROW_FOCUS } from '@/components/ui/clickableRow'
import { ChevronRight } from 'lucide-react'
import { useVirtualRows } from '@/hooks/useVirtualRows'
import { cn } from '@/lib/cn'
import { SeverityBadge } from './SeverityBadge'
import { STATUS_LABELS, type FindingBase } from './types'

const ROW_HEIGHT = 32

export interface FindingsTableProps<F extends FindingBase> {
  items: F[]
  selectedIndex: number
  onSelectIndex: (i: number) => void
  onOpen: (i: number) => void
  onReachEnd?: () => void
}

/**
 * Таблица находок: Severity, колонки модуля, статус. Модуль задаёт ширину
 * таблицы (класс min-w-[…]), заголовки и ячейки своих колонок.
 */
export function CollectorFindingsTable<F extends FindingBase>({ items, selectedIndex, onSelectIndex, onOpen, onReachEnd, minWidth, head, cells }: FindingsTableProps<F> & {
  minWidth: string
  head: ReactNode
  cells: (f: F) => ReactNode
}) {
  const { parentRef, rows, totalSize } = useVirtualRows(items.length, ROW_HEIGHT, selectedIndex, onReachEnd)

  return (
    <div ref={parentRef} className="h-full overflow-auto">
      <div className={`sticky top-0 z-10 flex ${minWidth} border-b border-grid bg-surface text-[11px] font-semibold tracking-wide text-text-secondary uppercase`}>
        <div className="w-28 shrink-0 px-2 py-2">Severity</div>
        {head}
        <div className="w-24 shrink-0 px-2 py-2">Статус</div>
      </div>
      <div style={{ height: totalSize, position: 'relative' }}>
        {rows.map((v) => {
          const f = items[v.index]
          const selected = v.index === selectedIndex
          return (
            <div key={f.id} {...clickableRow(() => { onSelectIndex(v.index); onOpen(v.index) })} className={cn(ROW_FOCUS, `absolute top-0 left-0 flex w-full ${minWidth} cursor-pointer items-center border-b border-grid text-xs`, selected ? 'bg-row-selected' : 'hover:bg-row-hover')} style={{ height: ROW_HEIGHT, transform: `translateY(${v.start}px)` }}>
              <div className="w-28 shrink-0 px-2"><SeverityBadge severity={f.severity} /></div>
              {cells(f)}
              <div className={cn('w-24 shrink-0 px-2', f.status === 'new' && 'text-risk-high', f.status === 'accepted' && 'text-kind-accepted', f.status === 'fixed' && 'text-kind-accepted')}>{STATUS_LABELS[f.status]}{f.allowlisted ? ' · allow' : ''}</div>
              <ChevronRight size={14} className="mr-2 ml-auto shrink-0 text-text-secondary/40" aria-hidden />
            </div>
          )
        })}
      </div>
    </div>
  )
}
