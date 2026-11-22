import { useTrendBadges } from '../../api/trends'
import { TrendBadge } from '../../components/TrendBadge'
import { clickableRow, ROW_FOCUS } from '@/components/ui/clickableRow'
import { useVirtualRows } from '@/hooks/useVirtualRows'
import { ChevronRight } from 'lucide-react'
import type { VulnItem, VulnSort } from '@/modules/vm/api/types'
import { CVSS_SOURCE_LABELS } from '@/modules/vm/api/types'
import { RiskBadge } from '@/modules/vm/components/RiskBadge'
import { StatusBadge } from '@/platform/findings/StatusBadge'
import { cn } from '@/lib/cn'
import { SortableTh } from '@/platform/table/SortableTh'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'

const ROW_HEIGHT = 32

const COLUMNS: ColumnDef[] = [
  { key: 'risk', label: 'Риск', width: 208 },
  { key: 'host', label: 'Хост', width: 240, flex: true },
  { key: 'ip', label: 'IP', width: 128 },
  { key: 'cve', label: 'CVE', width: 176 },
  { key: 'cvss', label: 'CVSS', width: 96 },
  { key: 'epss', label: 'EPSS', width: 80 },
  { key: 'exploit', label: 'Эксплойт', width: 96 },
  { key: 'msf', label: 'MSF', width: 80 },
  { key: 'crit', label: 'Крит.', width: 80 },
  { key: 'zone', label: 'Зона', width: 112 },
  { key: 'status', label: 'Статус', width: 176 },
  { key: 'open', label: '', width: 32, resizable: false },
]
const WITH_CHECK: ColumnDef[] = [{ key: 'check', label: 'Отметка', width: 32, resizable: false }, ...COLUMNS]
const SORT_KEYS: Partial<Record<string, VulnSort>> = {
  risk: 'risk_desc', host: 'host_asc', cve: 'cve_asc', cvss: 'cvss_desc', epss: 'epss_desc', exploit: 'exploits_desc',
}

interface Props {
  rememberKey?: string
  items: VulnItem[]
  selectedIndex: number
  sort: VulnSort
  onSort: (sort: VulnSort) => void
  onSelectIndex: (i: number) => void
  onOpen: (i: number) => void
  onReachEnd?: () => void
  /** Отмеченные для массовой смены ключи пар; без onCheck галочек нет (аудитор). */
  checked?: ReadonlySet<string>
  /** shift — отметить диапазон от предыдущей отмеченной строки. */
  onCheck?: (i: number, shift: boolean) => void
  onCheckAll?: (on: boolean) => void
}

export function VulnsTable({ rememberKey, items, selectedIndex, sort, onSort, onSelectIndex, onOpen, onReachEnd, checked, onCheck, onCheckAll }: Props) {
  const trends = useTrendBadges(items.map(item => item.cve_id))
  const { parentRef, rows: virtualRows, totalSize } = useVirtualRows(items.length, ROW_HEIGHT, selectedIndex, onReachEnd, rememberKey)

  const allChecked = items.length > 0 && items.every((i) => checked?.has(i.key))
  const cols = useColumnWidths('vm-vulns-columns', onCheck ? WITH_CHECK : COLUMNS)

  return (
    <div ref={parentRef} data-col-resize-root className="h-full overflow-auto">
      <div className="sticky top-0 z-10 grid items-center border-b border-grid bg-surface text-[11px] font-semibold tracking-wide text-text-secondary uppercase" style={cols.gridStyle}>
        {cols.columns.map((c) => c.key === 'check'
          ? <div key={c.key} className="pl-3"><input type="checkbox" aria-label="Отметить все загруженные" checked={allChecked} onChange={(e) => onCheckAll?.(e.target.checked)} /></div>
          : <SortableTh key={c.key} cols={cols} col={c} sortKey={SORT_KEYS[c.key]} ascending={c.key === 'host' || c.key === 'cve'} sort={sort} onSort={onSort}>{c.label}</SortableTh>)}
      </div>

      <div style={{ height: totalSize, position: 'relative' }}>
        {virtualRows.map((v) => {
          const item = items[v.index]
          const selected = v.index === selectedIndex
          return (
            <div
              key={item.key}
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
              {onCheck && (
                // Галочка не открывает карточку: клик и клавиши до строки не доходят.
                <div className="pl-3" onClick={(e) => e.stopPropagation()} onKeyDown={(e) => e.stopPropagation()}>
                  <input type="checkbox" aria-label="Отметить" checked={checked?.has(item.key) ?? false} onChange={() => undefined}
                    onClick={(e) => onCheck(v.index, e.shiftKey)} />
                </div>
              )}
              <div className="min-w-0 overflow-hidden px-2"><RiskBadge score={item.risk} level={item.level} /></div>
              <div className="min-w-0 truncate px-2 font-mono text-text" title={item.hostname}>{item.hostname}</div>
              <div className="min-w-0 truncate px-2 font-mono text-text-secondary">{item.ip}</div>
              <div className="flex min-w-0 items-center gap-1.5 px-2">
                <span className="min-w-0 truncate font-mono text-text">{item.cve_id}</span>
                {item.sbom_asset_id != null && <span className="text-[10px] text-text-secondary" title="Подтверждено бюллетенем производителя">SBOM</span>}
                {trends.data?.[item.cve_id] && <TrendBadge id={item.cve_id} reason={trends.data[item.cve_id].reason} />}
                {/* Колонки KEV нет (спека §5): признак — бейдж у CVE, вымогатели — в подсказке; при узкой колонке обрезается номер, а не бейдж. */}
                {item.kev && <span className="shrink-0 text-[10px] font-semibold text-risk-critical" title={item.kev_ransomware ? 'CISA KEV · ransomware' : 'CISA KEV'}>KEV</span>}
              </div>
              <div className="min-w-0 truncate px-2 font-mono tabular-nums text-text-secondary">
                {item.cvss ?? '—'}
                {item.cvss !== null && <span className="ml-1 text-[10px]">{CVSS_SOURCE_LABELS[item.cvss_source]}</span>}
              </div>
              <div className="min-w-0 truncate px-2 font-mono tabular-nums text-text-secondary">{item.epss === null ? '—' : item.epss.toFixed(3)}</div>
              <div className="min-w-0 truncate px-2 text-text-secondary">
                {item.exploitdb_type ? <span className="text-risk-high">{item.exploitdb_type} · {item.exploits_count}</span> : '—'}
              </div>
              <div className="min-w-0 truncate px-2 text-text-secondary">{item.msf_rank ?? '—'}</div>
              <div className="min-w-0 truncate px-2 text-text-secondary">{item.criticality || '—'}</div>
              <div className="min-w-0 truncate px-2 text-text-secondary" title={item.zone}>{item.zone || '—'}</div>
              <div className="flex min-w-0 items-center gap-1 overflow-hidden px-2" title={item.assignee_name ? `исполнитель: ${item.assignee_name}` : undefined}>
                <StatusBadge status={item.status} />
                {item.overdue && <span className="text-[11px] text-kind-1" title={`срок ${item.due_date ?? ''}`}>просрочена</span>}
              </div>
              <div className="flex justify-end pr-2"><ChevronRight size={14} className="shrink-0 text-text-secondary/40" aria-hidden /></div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
