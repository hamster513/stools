import { useState } from 'react'
import { ArrowDown, ArrowUp, ChevronLeft, ChevronRight, Radar } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { clickableRow, ROW_FOCUS } from '@/components/ui/clickableRow'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { cn } from '@/lib/cn'
import { useRouter, useSearchParams } from '@/lib/router'
import { ExportButton } from '@/platform/filters/ExportButton'
import { exportHref } from '@/platform/filters/exportHref'
import { FiltersButton, FilterChips, type FilterChip } from '@/platform/filters/FiltersBar'
import { useFiltersPanel } from '@/platform/filters/useFiltersPanel'
import { listFrom, toggleValue, valueChips } from '@/platform/findings/facets'
import { StatusBadge } from '@/platform/findings/StatusBadge'
import { STATUSES, STATUS_TITLES, type FindingStatus } from '@/platform/findings/types'
import { ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'
import { TH_FINDINGS_PATH, thFindingsParams, useThFindings } from '../api/queries'
import type { ThFindingSort, ThFindingsFilters } from '../api/types'
import { ruDay, ruStamp } from '../format'

const PAGE_SIZE = 100
const ROW_HEIGHT = 36

const COLUMNS: ColumnDef[] = [
  { key: 'status', label: 'Статус', width: 144 },
  { key: 'hunt', label: 'Хант', width: 360, flex: true },
  { key: 'query', label: 'Запрос', width: 80 },
  { key: 'night', label: 'Ночь', width: 104 },
  { key: 'events', label: 'Событий', width: 96, align: 'right' },
  { key: 'created', label: 'Найдено', width: 144 },
  { key: 'assignee', label: 'Исполнитель', width: 176 },
]

/** Колонка → поле сортировки сервера; колонки без поля (исполнитель) не сортируются. */
const SORT_OF: Record<string, ThFindingSort> = {
  status: 'status', hunt: 'hunt', query: 'query', night: 'night', events: 'events', created: 'created_at',
}

type Filters = Omit<ThFindingsFilters, 'limit' | 'offset'>

/** Фильтры из ссылки: «все находки ханта» ведёт сюда с `?hunt=<код>&status=all`. */
function filtersFrom(params: URLSearchParams): Filters {
  return {
    status: params.get('status') === 'all' ? 'all' : listFrom<FindingStatus>(params, 'status', STATUSES),
    hunt: listFrom(params, 'hunt'),
    date_from: params.get('date_from') || undefined,
    date_to: params.get('date_to') || undefined,
    limit_hit: params.get('limit_hit') === '1' ? true : undefined,
    sort: 'created_at',
    order: 'desc',
  }
}

/**
 * Очередь ночных находок Threat Hunting. Без выбранного статуса сервер отдаёт открытые;
 * фильтры живут в состоянии страницы, а стартуют из адреса (страница пересоздаётся при смене строки запроса).
 */
export function FindingsPage() {
  const { navigate } = useRouter()
  const params = useSearchParams()
  const [filters, setFilters] = useState<Filters>(() => filtersFrom(params))
  const [offset, setOffset] = useState(0)
  const filtersPanel = useFiltersPanel('siem-th-findings')
  const cols = useColumnWidths('siem-th-findings-columns', COLUMNS)
  const query = useThFindings({ ...filters, limit: PAGE_SIZE, offset })

  // Любой отбор возвращает на первую страницу.
  function update(patch: Partial<Filters>) {
    setFilters((f) => ({ ...f, ...patch }))
    setOffset(0)
  }
  function sortBy(sort: ThFindingSort) {
    update(filters.sort === sort ? { order: filters.order === 'asc' ? 'desc' : 'asc' } : { sort, order: sort === 'created_at' || sort === 'events' ? 'desc' : 'asc' })
  }

  const statuses = filters.status === 'all' ? undefined : filters.status
  const chips: FilterChip[] = []
  if (filters.status === 'all') chips.push({ label: 'Статус: любой', clear: () => update({ status: undefined }) })
  chips.push(...valueChips('Статус', statuses, (s) => STATUS_TITLES[s], (status) => update({ status })))
  chips.push(...valueChips('Хант', filters.hunt, (c) => c, (hunt) => update({ hunt })))
  if (filters.date_from) chips.push({ label: `Ночь с ${ruDay(filters.date_from)}`, clear: () => update({ date_from: undefined }) })
  if (filters.date_to) chips.push({ label: `Ночь по ${ruDay(filters.date_to)}`, clear: () => update({ date_to: undefined }) })
  if (filters.limit_hit) chips.push({ label: 'Достигнут лимит', clear: () => update({ limit_hit: undefined }) })

  const data = query.data
  const total = data?.total ?? 0
  const items = data?.items ?? []
  // Выбранный хант, которого нет в счётчиках (другие фильтры его исключили), остаётся в списке — иначе его не снять.
  const huntFacet: Record<string, number> = { ...Object.fromEntries((filters.hunt ?? []).map((c) => [c, 0])), ...data?.facets.hunt }
  const errorMessage = query.error instanceof ApiRequestError ? query.error.message : query.isError ? 'Не удалось загрузить находки' : null

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex shrink-0 flex-wrap items-center gap-3 border-b border-grid bg-surface px-4 py-2.5">
        <h1 className="text-sm font-semibold text-text">Находки Threat Hunting</h1>
        <FiltersButton open={filtersPanel.open} onToggle={filtersPanel.toggle} count={chips.length} />
        <ExportButton href={exportHref(`${TH_FINDINGS_PATH}/export`, thFindingsParams(filters))} total={total} disabled={query.isLoading} />
        <div className="font-mono text-xs tabular-nums text-text-secondary">{data ? `всего: ${total}` : ''}</div>
        {!filtersPanel.open && <FilterChips chips={chips} />}
      </header>

      <div className="flex min-h-0 flex-1">
        {filtersPanel.open && (
          <div className="flex h-full w-60 shrink-0 flex-col overflow-y-auto border-r border-grid bg-surface">
            <div className="border-b border-grid px-2 py-3">
              <div className="mb-1.5 px-2 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">Статус</div>
              {STATUSES.map((s) => (
                <FacetRow key={s} label={STATUS_TITLES[s]} count={data?.facets.status[s]} active={statuses?.includes(s) ?? false} onClick={() => update({ status: toggleValue(statuses, s) })} />
              ))}
              <FacetRow label="Любой статус" active={filters.status === 'all'} onClick={() => update({ status: filters.status === 'all' ? undefined : 'all' })} />
              <p className="mt-1 px-2 text-[11px] text-text-secondary">Ничего не выбрано — открытые.</p>
            </div>
            <div className="border-b border-grid px-2 py-3">
              <div className="mb-1.5 px-2 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">Хант</div>
              {Object.keys(huntFacet).length === 0 && <p className="px-2 text-[11px] text-text-secondary">нет находок</p>}
              {Object.entries(huntFacet).sort(([a], [b]) => a.localeCompare(b)).map(([code, count]) => (
                <FacetRow key={code} label={code} mono count={count} active={filters.hunt?.includes(code) ?? false} onClick={() => update({ hunt: toggleValue(filters.hunt, code) })} />
              ))}
            </div>
            <div className="flex flex-col gap-2 px-4 py-3">
              <div className="text-[11px] font-semibold tracking-wide text-text-secondary uppercase">Ночь</div>
              <label className="flex items-center justify-between gap-2 text-xs text-text-secondary">
                с
                <input type="date" value={filters.date_from ?? ''} onChange={(e) => update({ date_from: e.target.value || undefined })} className="rounded border border-border bg-app-bg px-2 py-1 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" />
              </label>
              <label className="flex items-center justify-between gap-2 text-xs text-text-secondary">
                по
                <input type="date" value={filters.date_to ?? ''} onChange={(e) => update({ date_to: e.target.value || undefined })} className="rounded border border-border bg-app-bg px-2 py-1 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" />
              </label>
              <label className="mt-1 flex items-center gap-1.5 text-xs text-text">
                <input type="checkbox" checked={filters.limit_hit ?? false} onChange={(e) => update({ limit_hit: e.target.checked || undefined })} className="accent-primary" />
                достигнут лимит
              </label>
            </div>
          </div>
        )}

        <div className="flex min-w-0 flex-1 flex-col bg-app-bg">
          {query.isLoading && <FullPageSpinner />}
          {errorMessage && <div className="p-6"><ErrorState message={errorMessage} onRetry={() => query.refetch()} /></div>}
          {data && !errorMessage && items.length === 0 && (
            <div className="p-6">
              <EmptyState
                icon={Radar}
                title="Находок нет"
                description={chips.length ? 'Под выбранные фильтры ничего не попало. Снимите фильтры, чтобы увидеть все открытые.' : 'Открытых находок нет: ночные прогоны ещё ничего не нашли или всё уже разобрано.'}
              />
            </div>
          )}
          {data && !errorMessage && items.length > 0 && (
            <>
              <div data-col-resize-root className="min-h-0 flex-1 overflow-auto">
                <div className="sticky top-0 z-10 grid border-b border-grid bg-surface text-[11px] tracking-wide text-text-secondary uppercase" style={cols.gridStyle}>
                  <ResizableHeader
                    cols={cols}
                    as="div"
                    className="px-2 py-2"
                    content={Object.fromEntries(COLUMNS.filter((c) => SORT_OF[c.key]).map((c) => [c.key, (
                      <SortLabel label={c.label} active={filters.sort === SORT_OF[c.key]} order={filters.order ?? 'desc'} onClick={() => sortBy(SORT_OF[c.key])} />
                    )]))}
                  />
                </div>
                {items.map((f) => (
                  <div
                    key={f.id}
                    {...clickableRow(() => navigate(`/siem/hunting/findings/${f.id}`))}
                    className={cn(ROW_FOCUS, 'grid cursor-pointer items-center border-b border-grid text-xs hover:bg-row-hover')}
                    style={{ ...cols.gridStyle, height: ROW_HEIGHT }}
                  >
                    <div className="min-w-0 px-2"><StatusBadge status={f.status} /></div>
                    <div className="min-w-0 truncate px-2" title={`${f.hunt_code} ${f.hunt_name}`}>
                      <span className="font-mono text-text">{f.hunt_code}</span> <span className="text-text-secondary">{f.hunt_name}</span>
                    </div>
                    <div className="min-w-0 truncate px-2 font-mono text-text-secondary">{f.query_id}</div>
                    <div className="min-w-0 truncate px-2 tabular-nums text-text-secondary">{ruDay(f.target_date)}</div>
                    <div className="min-w-0 px-2 text-right font-mono tabular-nums text-text">
                      {f.event_count}
                      {f.limit_hit && <span className="ml-1 text-kind-1" title="Достигнут лимит выборки: событий могло быть больше">!</span>}
                    </div>
                    <div className="min-w-0 truncate px-2 tabular-nums text-text-secondary">{ruStamp(f.created_at)}</div>
                    <div className="min-w-0 truncate px-2 text-text-secondary" title={f.assignee ?? undefined}>
                      {f.assignee ?? '—'}
                      {f.overdue && <span className="ml-1.5 text-[11px] text-kind-1">просрочено</span>}
                    </div>
                  </div>
                ))}
              </div>
              {total > PAGE_SIZE && (
                <div className="flex shrink-0 items-center justify-end gap-2 border-t border-grid bg-surface px-4 py-1.5">
                  <span className="font-mono text-xs tabular-nums text-text-secondary">{offset + 1}–{offset + items.length} из {total}</span>
                  <Button variant="ghost" onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))} disabled={offset === 0} aria-label="Предыдущая страница"><ChevronLeft size={14} aria-hidden /></Button>
                  <Button variant="ghost" onClick={() => setOffset(offset + PAGE_SIZE)} disabled={offset + PAGE_SIZE >= total} aria-label="Следующая страница"><ChevronRight size={14} aria-hidden /></Button>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}

function SortLabel({ label, active, order, onClick }: { label: string; active: boolean; order: 'asc' | 'desc'; onClick: () => void }) {
  const Arrow = order === 'asc' ? ArrowUp : ArrowDown
  return (
    <button type="button" onClick={onClick} title="Сортировать" className={cn('flex items-center gap-1 rounded uppercase focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring', active && 'text-text')}>
      {label}
      {active && <Arrow size={11} aria-hidden />}
    </button>
  )
}

/** Строка фасета: клик включает значение, повторный — снимает. */
function FacetRow({ label, count, active, mono, onClick }: { label: string; count?: number; active: boolean; mono?: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        'flex w-full items-center justify-between rounded px-2 py-1.5 text-left text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring',
        active ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text',
      )}
    >
      <span className={cn('truncate', mono && 'font-mono')}>{label}</span>
      {count !== undefined && <span className="font-mono text-[11px] tabular-nums">{count}</span>}
    </button>
  )
}
