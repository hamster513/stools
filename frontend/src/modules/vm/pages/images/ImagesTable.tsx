import { useEffect, useRef } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { AlertTriangle, ChevronRight } from 'lucide-react'
import { clickableRow, ROW_FOCUS } from '@/components/ui/clickableRow'
import type { ImageItem, ImageSort } from '@/modules/vm/api/types'
import { NO_RISK_TITLE, SCAN_STATUS_LABELS } from '@/modules/vm/api/types'
import { RiskBadge } from '@/modules/vm/components/RiskBadge'
import { cn } from '@/lib/cn'
import { SortableTh } from '@/platform/table/SortableTh'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'
import { date, megabytes } from './format'
import { TrivyCounts } from './TrivyCounts'

const ROW_HEIGHT = 40
const SHOWN_TAGS = 3

const COLUMNS: ColumnDef[] = [
  { key: 'image', label: 'Образ', width: 280, flex: true },
  { key: 'tags', label: 'Теги', width: 200 },
  { key: 'risk', label: 'Риск', width: 208 },
  { key: 'trivy', label: 'Trivy', width: 200 },
  { key: 'scan', label: 'Скан', width: 176 },
  { key: 'pushed', label: 'Отправлен', width: 128 },
  { key: 'size', label: 'Размер', width: 96 },
  { key: 'open', label: '', width: 32, resizable: false },
]
const SORT_KEYS: Partial<Record<string, ImageSort>> = {
  image: 'name', risk: 'risk_desc', trivy: 'trivy_desc', pushed: 'pushed_desc',
}

interface Props {
  items: ImageItem[]
  selectedIndex: number
  sort: ImageSort
  onSort: (sort: ImageSort) => void
  onSelectIndex: (i: number) => void
  onOpen: (i: number) => void
  onReachEnd?: () => void
}

/** Список образов: строка открывает страницу образа; j/k и Enter — на странице. */
export function ImagesTable({ items, selectedIndex, sort, onSort, onSelectIndex, onOpen, onReachEnd }: Props) {
  const parentRef = useRef<HTMLDivElement>(null)
  const virtualizer = useVirtualizer({ count: items.length, getScrollElement: () => parentRef.current, estimateSize: () => ROW_HEIGHT, overscan: 12 })

  useEffect(() => {
    if (selectedIndex >= 0 && selectedIndex < items.length) virtualizer.scrollToIndex(selectedIndex, { align: 'auto' })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedIndex])

  const virtualRows = virtualizer.getVirtualItems()
  const lastVisible = virtualRows.length ? virtualRows[virtualRows.length - 1].index : 0
  useEffect(() => {
    if (onReachEnd && items.length > 0 && lastVisible >= items.length - 20) onReachEnd()
  }, [lastVisible, items.length, onReachEnd])

  const cols = useColumnWidths('vm-images-columns', COLUMNS)

  return (
    <div ref={parentRef} data-col-resize-root className="h-full overflow-auto">
      <div className="sticky top-0 z-10 grid items-center border-b border-grid bg-surface text-[11px] font-semibold tracking-wide text-text-secondary uppercase" style={cols.gridStyle}>
        {cols.columns.map((c) => <SortableTh key={c.key} cols={cols} col={c} sortKey={SORT_KEYS[c.key]} sort={sort} onSort={onSort} ascending={SORT_KEYS[c.key] === 'name'}>{c.label}</SortableTh>)}
      </div>

      <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
        {virtualRows.map((v) => {
          const item = items[v.index]
          const selected = v.index === selectedIndex
          const extra = item.tags.length - SHOWN_TAGS
          return (
            <div
              key={item.id}
              {...clickableRow(() => {
                onSelectIndex(v.index)
                onOpen(v.index)
              })}
              className={cn(
                ROW_FOCUS,
                'absolute top-0 left-0 grid w-full cursor-pointer items-center border-b border-grid text-xs',
                selected ? 'bg-row-selected' : 'hover:bg-row-hover',
              )}
              style={{ ...cols.gridStyle, height: ROW_HEIGHT, transform: `translateY(${v.start}px)` }}
            >
              <div className="min-w-0 px-2">
                <div className="flex min-w-0 items-center gap-1.5">
                  <span className="min-w-0 truncate font-mono text-text" title={item.name}>{item.name}</span>
                  {item.sync_error && (
                    <span className="shrink-0 text-risk-medium" title={`Не обновлён в последней синхронизации: ${item.sync_error}`}>
                      <AlertTriangle size={12} aria-hidden />
                      <span className="sr-only">не обновлён в последней синхронизации</span>
                    </span>
                  )}
                </div>
                {item.platform && <div className="truncate text-[10px] text-text-secondary" title={item.platform}>{item.platform}</div>}
              </div>
              <div className="min-w-0 truncate px-2 font-mono text-text-secondary" title={item.tags.join(', ')}>
                {item.tags.length === 0 ? '—' : item.tags.slice(0, SHOWN_TAGS).join(', ')}
                {extra > 0 && <span className="ml-1 text-[10px]">+{extra}</span>}
              </div>
              <div className="min-w-0 overflow-hidden px-2">
                {item.risk_max !== null && item.level !== null
                  ? <RiskBadge score={item.risk_max} level={item.level} />
                  : <span className="text-text-secondary" title={NO_RISK_TITLE}>—</span>}
              </div>
              <div className="min-w-0 overflow-hidden px-2"><TrivyCounts trivy={item.trivy} /></div>
              <div className="min-w-0 px-2">
                <div className={cn('truncate', item.scan_status === 'error' ? 'text-risk-high' : 'text-text')}>{SCAN_STATUS_LABELS[item.scan_status] ?? item.scan_status}</div>
                {item.scanned_at && <div className="truncate text-[10px] text-text-secondary">{date(item.scanned_at)}</div>}
              </div>
              <div className="min-w-0 truncate px-2 font-mono tabular-nums text-text-secondary">{date(item.pushed_at)}</div>
              <div className="min-w-0 truncate px-2 text-right font-mono tabular-nums text-text-secondary">{megabytes(item.size)}</div>
              <div className="flex justify-end pr-2"><ChevronRight size={14} className="shrink-0 text-text-secondary/40" aria-hidden /></div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
