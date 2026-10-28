import { useEffect, useRef } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { Check, ChevronDown, ChevronRight } from 'lucide-react'
import { clickableRow, ROW_FOCUS } from '@/components/ui/clickableRow'
import type { ImageVulnItem, ImageVulnSort, TrivySeverity } from '@/modules/vm/api/types'
import { TRIVY_SEVERITY_LABELS } from '@/modules/vm/api/types'
import { RiskBadge } from '@/modules/vm/components/RiskBadge'
import { cn } from '@/lib/cn'
import { ResizeHandle } from '@/platform/table/ResizeHandle'
import { useColumnWidths, type ColumnDef, type ColumnWidths } from '@/platform/table/useColumnWidths'

const ROW_HEIGHT = 32

const COLUMNS: ColumnDef[] = [
  { key: 'cve', label: 'CVE', width: 176 },
  { key: 'package', label: 'Пакет', width: 224, flex: true },
  { key: 'installed', label: 'Установлена', width: 144 },
  { key: 'fixed', label: 'Исправлена', width: 144 },
  { key: 'trivy', label: 'Trivy', width: 128 },
  { key: 'risk', label: 'Риск', width: 208 },
  { key: 'epss', label: 'EPSS', width: 88 },
  { key: 'kev', label: 'KEV', width: 64 },
  { key: 'open', label: '', width: 32, resizable: false },
]
const SORT_KEYS: Partial<Record<string, ImageVulnSort>> = {
  cve: 'cve', package: 'package', trivy: 'severity_desc', risk: 'risk_desc',
}
const ASCENDING: ImageVulnSort[] = ['cve', 'package']

const TRIVY_TEXT: Record<TrivySeverity, string> = {
  critical: 'text-risk-critical',
  high: 'text-risk-high',
  medium: 'text-risk-medium',
  low: 'text-risk-low',
  unknown: 'text-text-secondary',
}

/** Оценка Trivy словом: цвет не единственный носитель смысла. */
export function TrivyBadge({ severity }: { severity: TrivySeverity }) {
  return <span className={cn('text-xs font-medium', TRIVY_TEXT[severity])}>{TRIVY_SEVERITY_LABELS[severity]}</span>
}

interface Props {
  items: ImageVulnItem[]
  /** Ключ строки: тройка (идентификатор, пакет, версия) — см. `vulnKey` в ImagePage. */
  rowKey: (item: ImageVulnItem) => string
  selectedIndex: number
  sort: ImageVulnSort
  onSort: (sort: ImageVulnSort) => void
  onSelectIndex: (i: number) => void
  onOpen: (i: number) => void
  onReachEnd?: () => void
}

// Свой заголовок вместо ResizableHeader: сортировка по щелчку и aria-sort остаются на ячейке.
function Th({ children, sortKey, sort, onSort, cols, col }: {
  children: React.ReactNode
  sortKey?: ImageVulnSort
  sort: ImageVulnSort
  onSort: (s: ImageVulnSort) => void
  cols: ColumnWidths
  col: ColumnDef
}) {
  const handle = col.resizable !== false && <ResizeHandle cols={cols} col={col.key} label={col.label} />
  // «сбросить» — в резиновой колонке, пока ширины изменены.
  const reset = col.flex && cols.customized && (
    <button type="button" onClick={cols.reset} className="mr-2 shrink-0 rounded font-normal tracking-normal text-text-secondary normal-case hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" title="Вернуть ширины колонок по умолчанию">сбросить</button>
  )
  if (!sortKey) return <div className="relative flex min-w-0 items-center"><div className="min-w-0 flex-1 px-2 py-2">{children}</div>{reset}{handle}</div>
  const active = sort === sortKey
  const ascending = ASCENDING.includes(sortKey)
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

/** Находки образа: строка открывает дровер расчёта риска; j/k и Enter — на странице. */
export function ImageVulnsTable({ items, rowKey, selectedIndex, sort, onSort, onSelectIndex, onOpen, onReachEnd }: Props) {
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

  const cols = useColumnWidths('vm-image-vulns-columns', COLUMNS)

  return (
    <div ref={parentRef} data-col-resize-root className="h-full overflow-auto">
      <div className="sticky top-0 z-10 grid items-center border-b border-grid bg-surface text-[11px] font-semibold tracking-wide text-text-secondary uppercase" style={cols.gridStyle}>
        {cols.columns.map((c) => <Th key={c.key} cols={cols} col={c} sortKey={SORT_KEYS[c.key]} sort={sort} onSort={onSort}>{c.label}</Th>)}
      </div>

      <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
        {virtualRows.map((v) => {
          const item = items[v.index]
          const selected = v.index === selectedIndex
          return (
            <div
              key={rowKey(item)}
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
              <div className={cn('min-w-0 truncate px-2 font-mono text-text', !item.is_cve && 'italic')} title={item.cve_id}>{item.cve_id}</div>
              <div className="min-w-0 truncate px-2 font-mono text-text" title={item.package}>{item.package}</div>
              <div className="min-w-0 truncate px-2 font-mono text-text-secondary" title={item.installed_version}>{item.installed_version || '—'}</div>
              <div className="min-w-0 truncate px-2 font-mono text-text-secondary" title={item.fixed_version ?? undefined}>
                {item.fixed_version || <span className="font-sans">нет</span>}
              </div>
              <div className="min-w-0 truncate px-2"><TrivyBadge severity={item.trivy_severity} /></div>
              <div className="min-w-0 overflow-hidden px-2">
                {item.risk !== null && item.level !== null
                  ? <RiskBadge score={item.risk} level={item.level} />
                  : <span className="text-text-secondary" title="риск не оценён: идентификатора нет в справочнике CVE">—</span>}
              </div>
              <div className="min-w-0 truncate px-2 font-mono tabular-nums text-text-secondary">
                {item.epss === null ? '—' : `${(item.epss * 100).toLocaleString('ru-RU', { maximumFractionDigits: 2 })} %`}
              </div>
              <div className="px-2">
                {item.kev ? <><Check size={14} className="text-risk-critical" aria-hidden /><span className="sr-only">в каталоге CISA KEV</span></> : <span className="text-text-secondary">—</span>}
              </div>
              <div className="flex justify-end pr-2"><ChevronRight size={14} className="shrink-0 text-text-secondary/40" aria-hidden /></div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
