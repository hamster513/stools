import { useMemo, useRef, useState } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { ChevronLeft, ChevronRight, Inbox } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { Spinner } from '@/components/ui/Spinner'
import { ExportButton } from '@/platform/filters/ExportButton'
import { ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'
import { EVENTS_PAGE_SIZE, thEventsExportHref, useThEvents } from '../api/queries'
import type { ThColumn } from '../api/types'

const ROW_HEIGHT = 28

function cell(value: unknown): string {
  if (value === null || value === undefined || value === '') return '—'
  return typeof value === 'object' ? JSON.stringify(value) : String(value)
}

/**
 * События находки: колонки — из `columns` самой находки (подписи запроса), значения — по порядку колонок.
 * Страницами по EVENTS_PAGE_SIZE строк; строки страницы рисуются виртуализированно, как в инвентаре правил.
 * Ширины колонок запоминаются на каждый запрос ханта (`storageKey`), а не на находку.
 */
export function EventsTable({ findingId, columns, storageKey }: { findingId: number; columns: ThColumn[]; storageKey: string }) {
  const [page, setPage] = useState(0)
  const events = useThEvents(findingId, page)
  const defs = useMemo<ColumnDef[]>(
    () => columns.map((c, i) => ({ key: c.field, label: c.label, width: c.field === 'time' ? 168 : 160, flex: i === columns.length - 1 })),
    [columns],
  )
  const cols = useColumnWidths(storageKey, defs)
  const scroller = useRef<HTMLDivElement>(null)
  const rows = events.data?.rows ?? []
  const virtualizer = useVirtualizer({ count: rows.length, getScrollElement: () => scroller.current, estimateSize: () => ROW_HEIGHT, overscan: 12 })

  const total = events.data?.total ?? 0
  const pages = Math.max(1, Math.ceil(total / EVENTS_PAGE_SIZE))
  const from = total === 0 ? 0 : page * EVENTS_PAGE_SIZE + 1
  const to = page * EVENTS_PAGE_SIZE + rows.length

  function go(next: number) {
    setPage(next)
    scroller.current?.scrollTo({ top: 0 })
  }

  return (
    <section className="flex min-h-0 flex-col rounded border border-grid bg-surface">
      <div className="flex shrink-0 flex-wrap items-center gap-3 border-b border-grid px-3 py-2">
        <h2 className="text-sm font-semibold text-text">События</h2>
        <ExportButton href={thEventsExportHref(findingId)} total={events.data?.total} disabled={events.isLoading} />
        <span className="font-mono text-xs tabular-nums text-text-secondary">{total > 0 ? `${from}–${to} из ${total}` : ''}</span>
        <div className="ml-auto flex items-center gap-2">
          {events.isFetching && !events.isLoading && <Spinner />}
          <Button variant="ghost" onClick={() => go(page - 1)} disabled={page === 0} aria-label="Предыдущая страница"><ChevronLeft size={14} aria-hidden /></Button>
          <span className="font-mono text-xs tabular-nums text-text-secondary">{page + 1} / {pages}</span>
          <Button variant="ghost" onClick={() => go(page + 1)} disabled={page + 1 >= pages} aria-label="Следующая страница"><ChevronRight size={14} aria-hidden /></Button>
        </div>
      </div>
      {events.isLoading ? (
        <div className="flex justify-center py-10"><Spinner /></div>
      ) : events.isError ? (
        <div className="p-4"><ErrorState message={events.error instanceof ApiRequestError ? events.error.message : 'Не удалось загрузить события'} onRetry={() => events.refetch()} /></div>
      ) : rows.length === 0 ? (
        <div className="p-4"><EmptyState icon={Inbox} title="Событий нет" description="В этой находке нет событий на выбранной странице." /></div>
      ) : (
        <div ref={scroller} data-col-resize-root className="max-h-[32rem] min-h-0 flex-1 overflow-auto">
          <div className="sticky top-0 z-10 grid border-b border-grid bg-surface text-[11px] tracking-wide text-text-secondary uppercase" style={cols.gridStyle}>
            <ResizableHeader cols={cols} as="div" className="px-2 py-2" />
          </div>
          <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
            {virtualizer.getVirtualItems().map((row) => (
              <div
                key={page * EVENTS_PAGE_SIZE + row.index}
                className="absolute top-0 left-0 grid w-full items-center border-b border-grid text-xs hover:bg-row-hover"
                style={{ ...cols.gridStyle, height: ROW_HEIGHT, transform: `translateY(${row.start}px)` }}
              >
                {columns.map((c, i) => {
                  const text = cell(rows[row.index][i])
                  return <div key={c.field} className="min-w-0 truncate px-2 font-mono text-text" title={text}>{text}</div>
                })}
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  )
}
