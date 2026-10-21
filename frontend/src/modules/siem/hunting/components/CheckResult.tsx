import { useMemo, useRef } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { Button } from '@/components/ui/Button'
import { cn } from '@/lib/cn'
import { ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'
import type { CheckQueryOut, CheckWindow } from '../api/types'
import { ruStamp } from '../format'

const ROW_HEIGHT = 28
// Не FIELD: тот растягивает поле на всю ширину, а выбор окна стоит в строке рядом с кнопкой.
const SELECT = 'rounded border border-border bg-app-bg px-2 py-1 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring disabled:opacity-60'

const WINDOWS: [CheckWindow, string][] = [['1h', 'за час'], ['24h', 'за сутки'], ['7d', 'за неделю']]

function cell(value: unknown): string {
  if (value === null || value === undefined || value === '') return '—'
  return typeof value === 'object' ? JSON.stringify(value) : String(value)
}

const seconds = (ms: number) => `за ${(ms / 1000).toLocaleString('ru-RU', { minimumFractionDigits: 1, maximumFractionDigits: 1 })} с`

/** Выбор окна проверки: один и тот же у запроса и у «Проверить все запросы» в шапке ханта. */
export function WindowSelect({ value, onChange, disabled, className }: {
  value: CheckWindow
  onChange: (value: CheckWindow) => void
  disabled?: boolean
  className?: string
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value as CheckWindow)}
      disabled={disabled}
      aria-label="Окно проверки"
      className={cn(SELECT, className)}
    >
      {WINDOWS.map(([w, label]) => <option key={w} value={w}>{label}</option>)}
    </select>
  )
}

/**
 * Результат проверки запроса: сводка и события таблицей в стиле таблицы находки — те же подписи колонок,
 * ширины запоминаются по `storageKey` (тот же ключ, что у событий находки этого запроса), строки виртуализированы.
 * Строк не больше лимита проверки, все уже на клиенте — страниц нет.
 */
export function CheckResult({ result, storageKey, onHide }: { result: CheckQueryOut; storageKey: string; onHide: () => void }) {
  const { columns, rows } = result
  const defs = useMemo<ColumnDef[]>(
    () => columns.map((c, i) => ({ key: c.field, label: c.label, width: c.field === 'time' ? 168 : 160, flex: i === columns.length - 1 })),
    [columns],
  )
  const cols = useColumnWidths(storageKey, defs)
  const scroller = useRef<HTMLDivElement>(null)
  const virtualizer = useVirtualizer({ count: rows.length, getScrollElement: () => scroller.current, estimateSize: () => ROW_HEIGHT, overscan: 12 })

  // Сообщение сервера уже несёт счёт, окно и отметку о лимите; к нему — период и время ответа MaxPatrol.
  const summary = [result.message, `${ruStamp(result.period_from)} – ${ruStamp(result.period_to)}`, seconds(result.duration_ms)]

  return (
    <section className="mt-2 flex min-h-0 flex-col rounded border border-grid bg-surface" aria-label="Результат проверки">
      <div className="flex shrink-0 flex-wrap items-center gap-3 border-b border-grid px-3 py-2">
        <span className="text-xs text-text" role="status">
          {summary.map((part, i) => (
            <span key={i} className={i === 0 ? 'font-semibold' : 'tabular-nums text-text-secondary'}>{i > 0 && ' · '}{part}</span>
          ))}
        </span>
        <Button variant="ghost" onClick={onHide} className="ml-auto px-2 py-0.5 text-xs">Скрыть</Button>
      </div>
      {rows.length > 0 && (
        <div ref={scroller} data-col-resize-root className="max-h-[32rem] min-h-0 overflow-auto">
          <div className="sticky top-0 z-10 grid border-b border-grid bg-surface text-[11px] tracking-wide text-text-secondary uppercase" style={cols.gridStyle}>
            <ResizableHeader cols={cols} as="div" className="px-2 py-2" />
          </div>
          <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
            {virtualizer.getVirtualItems().map((row) => (
              <div
                key={row.index}
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
