import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import type { InfiniteData, UseInfiniteQueryResult } from '@tanstack/react-query'
import { FilterX, Search } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { useSearchParams } from '@/lib/router'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { FiltersButton, FilterChips, type FilterChip } from '@/platform/filters/FiltersBar'
import { useFiltersPanel } from '@/platform/filters/useFiltersPanel'
import { useMe } from '@/api/auth'
import { useCan } from '@/lib/can'
import { BulkBar } from '@/platform/findings/BulkBar'
import { findingFacetChips, findingFacetParams } from '@/platform/findings/facets'
import { useUsersDirectory } from '@/platform/findings/queries'
import { STATUSES, type FindingStatus } from '@/platform/findings/types'
import { FacetPanel } from './FacetPanel'
import type { FindingsTableProps } from './FindingsTable'
import { SEVERITY_LABELS, type FindingBase, type FindingDelta, type FindingFilters, type FindingsQuery, type FindingsResponse, type Severity } from './types'

const DELTA_LABELS: Record<FindingDelta, string> = { new: 'появились в этом снапшоте', same: 'были и раньше', gone: 'нет в последнем снапшоте' }

/** Статусы из ссылки: коды через запятую или `all`; незнакомые коды отбрасываются. */
function statusesFrom(raw: string | null): FindingStatus[] | undefined {
  if (!raw) return undefined
  if (raw === 'all') return [...STATUSES]
  const picked = raw.split(',').filter((s): s is FindingStatus => (STATUSES as string[]).includes(s))
  return picked.length ? picked : undefined
}

function filtersFrom(params: URLSearchParams): FindingFilters {
  const delta = params.get('delta')
  return {
    check: params.get('check') ?? undefined,
    severity: (params.get('severity') as Severity | null) ?? undefined,
    delta: delta === 'new' || delta === 'same' || delta === 'gone' ? delta : undefined,
    status: statusesFrom(params.get('status')),
    assignee: params.get('assignee') ?? undefined,
    overdue: params.get('overdue') === 'true' || undefined,
    risk_expiring: params.get('risk_expiring') === 'true' || undefined,
  }
}

function isTypingTarget(el: EventTarget | null): boolean {
  return el instanceof HTMLElement && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable)
}

/**
 * Находки снапшота: по умолчанию — последнего снапшота области (домена,
 * сервера). Фасеты, поиск, клавиши j/k, «/», Enter, Esc. useFindings — хук
 * модуля: его аргументы собирает страница из фильтров и поиска. filtersKey —
 * ключ страницы для запоминания, открыта ли панель фильтров (у каждого модуля свой).
 * Статусы находок — общие (platform/findings): галочки и полоса массовой смены
 * для области module/scopeId; `?key=` в адресе открывает карточку находки.
 * onChanged — модуль обновляет свои списки и обзор после смены статусов.
 */
export function CollectorFindingsPage<F extends FindingBase>({ module, scopeId, onChanged, filtersKey, loading, lastSnapshotId, useFindings, searchFromUrl = false, searchPlaceholder, emptyDescription, table, drawer }: {
  module: string
  scopeId: number
  onChanged: () => void
  filtersKey: string
  loading: boolean
  lastSnapshotId: number | undefined
  useFindings: (snapshotId: number | undefined, query: Omit<FindingsQuery, 'limit' | 'offset'>) => UseInfiniteQueryResult<InfiniteData<FindingsResponse<F>>, ApiRequestError>
  searchFromUrl?: boolean
  searchPlaceholder: string
  emptyDescription: string
  table: (props: FindingsTableProps<F>) => ReactNode
  drawer: (findingKey: string | null, snapshotId: number | undefined, onClose: () => void) => ReactNode
}) {
  const params = useSearchParams()
  const snapshotId = params.get('snapshot') ? Number(params.get('snapshot')) : lastSnapshotId
  const [filters, setFilters] = useState<FindingFilters>(() => filtersFrom(params))
  const [searchInput, setSearchInput] = useState(searchFromUrl ? (params.get('q') ?? '') : '')
  const q = useDebouncedValue(searchInput, 250)
  const [selectedIndex, setSelectedIndex] = useState(0)
  const [openKey, setOpenKey] = useState<string | null>(() => params.get('key'))
  const [checked, setChecked] = useState<ReadonlySet<string>>(new Set())
  const [anchor, setAnchor] = useState<number | null>(null)
  const searchRef = useRef<HTMLInputElement>(null)
  const filtersPanel = useFiltersPanel(filtersKey)
  const { write } = useCan()
  const me = useMe()
  const directory = useUsersDirectory()
  const names = useMemo(() => new Map((directory.data ?? []).map((u) => [u.login, u.display_name || u.login])), [directory.data])

  const queryArgs = useMemo<Omit<FindingsQuery, 'limit' | 'offset'>>(() => ({
    check: filters.check, severity: filters.severity, allowlisted: filters.allowlisted, delta: filters.delta,
    ...findingFacetParams(filters), q: q || undefined,
  }), [filters, q])
  const query = useFindings(snapshotId, queryArgs)
  const items = useMemo(() => query.data?.pages.flatMap((p) => p.items) ?? [], [query.data])
  const first = query.data?.pages[0]
  const total = first?.total ?? 0
  useEffect(() => { setSelectedIndex(0); setChecked(new Set()); setAnchor(null) }, [queryArgs, snapshotId])
  const selected: F | null = items[selectedIndex] ?? null

  function toggle<K extends keyof FindingFilters>(key: K, value: FindingFilters[K]) { setFilters((prev) => ({ ...prev, [key]: value })) }
  function clearAll() { setFilters({}); setSearchInput('') }
  function check(i: number, shift: boolean) {
    const on = !checked.has(items[i].key)
    const [from, to] = shift && anchor !== null ? [Math.min(anchor, i), Math.max(anchor, i)] : [i, i]
    const next = new Set(checked)
    for (const f of items.slice(from, to + 1)) {
      if (on) next.add(f.key)
      else next.delete(f.key)
    }
    setChecked(next)
    setAnchor(i)
  }
  function changed() { setChecked(new Set()); setAnchor(null); onChanged() }
  // Что выбрано, пока панель свёрнута: фильтр из ссылки не должен действовать незаметно.
  const chips: FilterChip[] = findingFacetChips(filters, (next) => setFilters((prev) => ({ ...prev, ...next })), names)
  if (filters.delta) chips.push({ label: DELTA_LABELS[filters.delta], clear: () => toggle('delta', undefined) })
  if (filters.severity) chips.push({ label: `severity ${SEVERITY_LABELS[filters.severity]}`, clear: () => toggle('severity', undefined) })
  if (filters.allowlisted !== undefined) chips.push({ label: filters.allowlisted ? 'в allowlist (понижено до Low)' : 'не в allowlist', clear: () => toggle('allowlisted', undefined) })
  if (filters.check) chips.push({ label: `проверка ${first?.check_titles[filters.check] ?? filters.check}`, clear: () => toggle('check', undefined) })

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') { if (openKey !== null) return setOpenKey(null); if (document.activeElement instanceof HTMLElement) document.activeElement.blur(); return }
      if (isTypingTarget(e.target)) return
      if (e.key === '/') { e.preventDefault(); searchRef.current?.focus(); return }
      if (e.key === 'j') { e.preventDefault(); setSelectedIndex((i) => Math.min(items.length - 1, i + 1)); return }
      if (e.key === 'k') { e.preventDefault(); setSelectedIndex((i) => Math.max(0, i - 1)); return }
      if (e.key === 'Enter' && selected) { e.preventDefault(); setOpenKey(selected.key) }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [items.length, selected, openKey])

  const hasFilters = Object.values(filters).some((v) => v !== undefined) || q !== ''
  const errorMessage = query.error instanceof ApiRequestError ? query.error.message : query.isError ? 'Не удалось загрузить находки' : null
  if (loading) return <FullPageSpinner />
  if (snapshotId === undefined) {
    return <div className="p-6"><EmptyState icon={FilterX} title="Снапшотов нет" description={emptyDescription} /></div>
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex shrink-0 flex-wrap items-center gap-3 border-b border-grid bg-surface px-4 py-2.5">
        <h1 className="text-sm font-semibold text-text">Находки</h1>
        <span className="font-mono text-xs text-text-secondary">снапшот #{snapshotId}</span>
        <FiltersButton open={filtersPanel.open} onToggle={filtersPanel.toggle} count={chips.length} />
        <div className="relative max-w-sm flex-1">
          <Search size={14} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-text-secondary" aria-hidden />
          <input ref={searchRef} value={searchInput} onChange={(e) => setSearchInput(e.target.value)} placeholder={searchPlaceholder} className="w-full rounded border border-border bg-app-bg py-1.5 pr-3 pl-8 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" />
        </div>
        {hasFilters && <button type="button" onClick={clearAll} className="flex items-center gap-1.5 rounded px-2 py-1 text-xs text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"><FilterX size={13} aria-hidden /> Сбросить</button>}
        {first?.compared_to.previous_id != null && <span className="text-[11px] text-text-secondary">к #{first.compared_to.previous_id}: <span className="text-risk-high">+{first.compared_to.new}</span> / <span className="text-kind-accepted">−{first.compared_to.fixed}</span></span>}
        <div className="font-mono text-xs tabular-nums text-text-secondary">{query.data ? (items.length < total ? `${items.length} из ${total}` : total) : '…'}</div>
        {!filtersPanel.open && <FilterChips chips={chips} />}
      </header>
      {write && <BulkBar module={module} scopeId={scopeId} keys={[...checked]} total={total} onDone={changed} onClear={() => setChecked(new Set())} />}
      <div className="flex min-h-0 flex-1">
        {filtersPanel.open && <FacetPanel facets={first?.facets ?? null} titles={first?.check_titles ?? {}} filters={filters} onToggle={toggle} total={total} myLogin={me.data?.login} names={names} />}
        <div className="min-w-0 flex-1 bg-app-bg">
          {query.isLoading && <FullPageSpinner />}
          {errorMessage && <div className="p-6"><ErrorState message={errorMessage} onRetry={() => query.refetch()} /></div>}
          {!query.isLoading && !errorMessage && items.length === 0 && (
            <div className="p-6"><EmptyState icon={FilterX} title={hasFilters ? 'Ничего не найдено' : 'Открытых находок нет'} description={hasFilters ? 'Ни одна находка не подходит под фильтры.' : 'В этом снапшоте нет открытых находок; остальные — в фильтре по статусу.'} /></div>
          )}
          {!query.isLoading && !errorMessage && items.length > 0 && (
            table({
              items, selectedIndex, onSelectIndex: setSelectedIndex, onOpen: (i) => setOpenKey(items[i].key),
              onReachEnd: () => { if (query.hasNextPage && !query.isFetchingNextPage) query.fetchNextPage() },
              ...(write ? { checked, onCheck: check, onCheckAll: (on: boolean) => setChecked(on ? new Set(items.map((f) => f.key)) : new Set()) } : {}),
            })
          )}
        </div>
      </div>
      {drawer(openKey, snapshotId, () => setOpenKey(null))}
    </div>
  )
}
