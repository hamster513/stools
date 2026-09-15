import { useEffect, useRef } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { ChevronDown, ChevronRight } from 'lucide-react'
import type { VulnItem, VulnSort } from '@/modules/vm/api/types'
import { CVSS_SOURCE_LABELS } from '@/modules/vm/api/types'
import { RiskBadge } from '@/modules/vm/components/RiskBadge'
import { cn } from '@/lib/cn'

const ROW_HEIGHT = 32

interface Props {
  items: VulnItem[]
  selectedIndex: number
  sort: VulnSort
  onSort: (sort: VulnSort) => void
  onSelectIndex: (i: number) => void
  onOpen: (i: number) => void
  onReachEnd?: () => void
}

function Th({
  children,
  className,
  sortKey,
  sort,
  onSort,
}: {
  children: React.ReactNode
  className: string
  sortKey?: VulnSort
  sort: VulnSort
  onSort: (s: VulnSort) => void
}) {
  if (!sortKey) return <div className={cn('px-2 py-2', className)}>{children}</div>
  const active = sort === sortKey
  return (
    <button
      type="button"
      onClick={() => onSort(sortKey)}
      className={cn('flex items-center gap-1 px-2 py-2 text-left uppercase hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring', className, active && 'text-text')}
      aria-sort={active ? 'descending' : 'none'}
    >
      {children}
      {active && <ChevronDown size={11} aria-hidden />}
    </button>
  )
}

export function VulnsTable({ items, selectedIndex, sort, onSort, onSelectIndex, onOpen, onReachEnd }: Props) {
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

  return (
    <div ref={parentRef} className="h-full overflow-auto">
      <div className="sticky top-0 z-10 flex min-w-[1240px] border-b border-grid bg-surface text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
        <Th className="w-52 shrink-0" sortKey="risk_desc" sort={sort} onSort={onSort}>Риск</Th>
        <Th className="min-w-[240px] flex-1" sortKey="host_asc" sort={sort} onSort={onSort}>Хост</Th>
        <Th className="w-32 shrink-0" sort={sort} onSort={onSort}>IP</Th>
        <Th className="w-36 shrink-0" sortKey="cve_asc" sort={sort} onSort={onSort}>CVE</Th>
        <Th className="w-24 shrink-0" sortKey="cvss_desc" sort={sort} onSort={onSort}>CVSS</Th>
        <Th className="w-20 shrink-0" sortKey="epss_desc" sort={sort} onSort={onSort}>EPSS</Th>
        <Th className="w-24 shrink-0" sortKey="exploits_desc" sort={sort} onSort={onSort}>Эксплойт</Th>
        <Th className="w-20 shrink-0" sort={sort} onSort={onSort}>MSF</Th>
        <Th className="w-20 shrink-0" sort={sort} onSort={onSort}>Крит.</Th>
        <Th className="w-28 shrink-0" sort={sort} onSort={onSort}>Зона</Th>
      </div>

      <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
        {virtualRows.map((v) => {
          const item = items[v.index]
          const selected = v.index === selectedIndex
          return (
            <div
              key={`${item.host_id}:${item.cve_id}`}
              onClick={() => {
                onSelectIndex(v.index)
                onOpen(v.index)
              }}
              className={cn(
                'absolute top-0 left-0 flex w-full min-w-[1240px] cursor-pointer items-center border-b border-grid text-xs',
                selected ? 'bg-row-selected' : 'hover:bg-row-hover',
              )}
              style={{ height: ROW_HEIGHT, transform: `translateY(${v.start}px)` }}
            >
              <div className="w-52 shrink-0 px-2"><RiskBadge score={item.risk} level={item.level} /></div>
              <div className="min-w-[240px] flex-1 truncate px-2 font-mono text-text" title={item.hostname}>{item.hostname}</div>
              <div className="w-32 shrink-0 truncate px-2 font-mono text-text-secondary">{item.ip}</div>
              <div className="w-36 shrink-0 px-2 font-mono text-text">{item.cve_id}</div>
              <div className="w-24 shrink-0 px-2 font-mono tabular-nums text-text-secondary">
                {item.cvss ?? '—'}
                {item.cvss !== null && <span className="ml-1 text-[10px]">{CVSS_SOURCE_LABELS[item.cvss_source]}</span>}
              </div>
              <div className="w-20 shrink-0 px-2 font-mono tabular-nums text-text-secondary">{item.epss === null ? '—' : item.epss.toFixed(3)}</div>
              <div className="w-24 shrink-0 truncate px-2 text-text-secondary">
                {item.exploitdb_type ? <span className="text-risk-high">{item.exploitdb_type} · {item.exploits_count}</span> : '—'}
              </div>
              <div className="w-20 shrink-0 truncate px-2 text-text-secondary">{item.msf_rank ?? '—'}</div>
              <div className="w-20 shrink-0 truncate px-2 text-text-secondary">{item.criticality || '—'}</div>
              <div className="w-28 shrink-0 truncate px-2 text-text-secondary" title={item.zone}>{item.zone || '—'}</div>
              <ChevronRight size={14} className="mr-2 ml-auto shrink-0 text-text-secondary/40" aria-hidden />
            </div>
          )
        })}
      </div>
    </div>
  )
}
