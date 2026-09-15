import { useEffect, useRef } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { ChevronRight } from 'lucide-react'
import type { Finding } from '@/modules/ad/api/types'
import { STATUS_LABELS } from '@/modules/ad/api/types'
import { SeverityBadge } from '@/modules/ad/components/SeverityBadge'
import { cn } from '@/lib/cn'

const ROW_HEIGHT = 32

export function FindingsTable({ items, selectedIndex, onSelectIndex, onOpen, onReachEnd }: { items: Finding[]; selectedIndex: number; onSelectIndex: (i: number) => void; onOpen: (i: number) => void; onReachEnd?: () => void }) {
  const parentRef = useRef<HTMLDivElement>(null)
  const virtualizer = useVirtualizer({ count: items.length, getScrollElement: () => parentRef.current, estimateSize: () => ROW_HEIGHT, overscan: 12 })
  useEffect(() => {
    if (selectedIndex >= 0 && selectedIndex < items.length) virtualizer.scrollToIndex(selectedIndex, { align: 'auto' })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedIndex])
  const rows = virtualizer.getVirtualItems()
  const last = rows.length ? rows[rows.length - 1].index : 0
  useEffect(() => {
    if (onReachEnd && items.length > 0 && last >= items.length - 20) onReachEnd()
  }, [last, items.length, onReachEnd])

  return (
    <div ref={parentRef} className="h-full overflow-auto">
      <div className="sticky top-0 z-10 flex min-w-[1100px] border-b border-grid bg-surface text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
        <div className="w-28 shrink-0 px-2 py-2">Severity</div>
        <div className="w-52 shrink-0 px-2 py-2">Проверка</div>
        <div className="w-56 shrink-0 px-2 py-2">Identity</div>
        <div className="min-w-[240px] flex-1 px-2 py-2">Цель</div>
        <div className="w-48 shrink-0 px-2 py-2">Право / детали</div>
        <div className="w-24 shrink-0 px-2 py-2">Статус</div>
      </div>
      <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
        {rows.map((v) => {
          const f = items[v.index]
          const selected = v.index === selectedIndex
          const detail = f.right || (typeof f.details.details === 'string' ? f.details.details : '') || (typeof f.details.delegation_type === 'string' ? f.details.delegation_type : '')
          return (
            <div key={f.id} onClick={() => { onSelectIndex(v.index); onOpen(v.index) }} className={cn('absolute top-0 left-0 flex w-full min-w-[1100px] cursor-pointer items-center border-b border-grid text-xs', selected ? 'bg-row-selected' : 'hover:bg-row-hover')} style={{ height: ROW_HEIGHT, transform: `translateY(${v.start}px)` }}>
              <div className="w-28 shrink-0 px-2"><SeverityBadge severity={f.severity} /></div>
              <div className="w-52 shrink-0 truncate px-2 text-text" title={f.check_title}>{f.check_title}</div>
              <div className="w-56 shrink-0 truncate px-2 font-mono text-text" title={f.identity}>{f.identity || '—'}</div>
              <div className="min-w-[240px] flex-1 truncate px-2 font-mono text-text-secondary" title={f.target}>{f.target}</div>
              <div className="w-48 shrink-0 truncate px-2 text-text-secondary" title={detail}>{detail}</div>
              <div className={cn('w-24 shrink-0 px-2', f.status === 'new' && 'text-risk-high', f.status === 'accepted' && 'text-kind-accepted', f.status === 'fixed' && 'text-kind-accepted')}>{STATUS_LABELS[f.status]}{f.allowlisted ? ' · allow' : ''}</div>
              <ChevronRight size={14} className="mr-2 ml-auto shrink-0 text-text-secondary/40" aria-hidden />
            </div>
          )
        })}
      </div>
    </div>
  )
}
