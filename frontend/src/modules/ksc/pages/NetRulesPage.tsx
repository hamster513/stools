import { useMemo, useState } from 'react'
import { FilterX, Search } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useNetRules } from '@/modules/ksc/api/queries'
import { NET_ACTION_LABELS, NET_DIRECTION_LABELS, type NetRuleItem } from '@/modules/ksc/api/types'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { FiltersButton, FilterChips, type FilterChip } from '@/platform/filters/FiltersBar'
import { useFiltersPanel } from '@/platform/filters/useFiltersPanel'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { FacetPanel, FacetRow, FacetSection } from './policies/Facets'
import { LoadMore, ObjectsEmpty, PolicyCell, PolicyFacet, SnapshotSection, UndescribedNote } from './objects/ObjectsParts'

interface Filters {
  policy?: { id: number; name: string }
  action?: string
  direction?: string
  enabled?: boolean
}

const actionLabel = (a: string) => NET_ACTION_LABELS[a] ?? (a || '—')
const directionLabel = (d: string) => NET_DIRECTION_LABELS[d] ?? (d || '—')

function Rows({ items, inPolicy }: { items: NetRuleItem[]; inPolicy: boolean }) {
  return (
    <div className="min-w-[1480px]">
      <div className="sticky top-0 z-10 flex border-b border-grid bg-surface text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
        <div className="min-w-[220px] flex-1 px-2 py-2">Название</div>
        <div className="w-28 shrink-0 px-2 py-2">Слой</div>
        <div className="w-12 shrink-0 px-2 py-2 text-right">№</div>
        <div className="w-24 shrink-0 px-2 py-2">Действие</div>
        <div className="w-24 shrink-0 px-2 py-2">Направление</div>
        <div className="w-20 shrink-0 px-2 py-2">Протокол</div>
        <div className="w-28 shrink-0 px-2 py-2">Локальные порты</div>
        <div className="w-28 shrink-0 px-2 py-2">Удалённые порты</div>
        <div className="w-48 shrink-0 px-2 py-2">Адреса</div>
        <div className="w-20 shrink-0 px-2 py-2">Включено</div>
        <div className="w-56 shrink-0 px-2 py-2">{inPolicy ? 'Профиль' : 'Политика / профиль'}</div>
      </div>
      {items.map((r) => (
        <div key={r.id} className="flex items-start border-b border-grid py-2 text-xs">
          <div className="min-w-[220px] flex-1 px-2 break-words text-text">{r.name || '—'}</div>
          <div className="w-28 shrink-0 truncate px-2 text-text-secondary" title={r.layer}>{r.layer || '—'}</div>
          <div className="w-12 shrink-0 px-2 text-right font-mono tabular-nums text-text-secondary">{r.position}</div>
          <div className="w-24 shrink-0 px-2 text-text-secondary">{actionLabel(r.action)}</div>
          <div className="w-24 shrink-0 px-2 text-text-secondary">{directionLabel(r.direction)}</div>
          <div className="w-20 shrink-0 px-2 text-text-secondary">{r.protocol || '—'}</div>
          <div className="w-28 shrink-0 px-2 font-mono break-all text-text-secondary">{r.local_ports || '—'}</div>
          <div className="w-28 shrink-0 px-2 font-mono break-all text-text-secondary">{r.remote_ports || '—'}</div>
          <div className="w-48 shrink-0 px-2 font-mono break-all text-text-secondary">{r.addresses || '—'}</div>
          <div className="w-20 shrink-0 px-2 text-text-secondary">{r.enabled ? 'да' : 'нет'}</div>
          <div className="w-56 shrink-0 px-2"><PolicyCell policyName={r.policy_name} profile={r.profile} inPolicy={inPolicy} /></div>
        </div>
      ))}
    </div>
  )
}

/** Сетевые правила снапшота: поиск по названию, адресу и порту, фильтры чипами. С `policyId` — по одной политике. */
export function NetRulesTable({ snapshotId, policyId }: { snapshotId: number; serverId: number; policyId?: number }) {
  const inPolicy = policyId !== undefined
  const [filters, setFilters] = useState<Filters>({})
  const [searchInput, setSearchInput] = useState('')
  const q = useDebouncedValue(searchInput, 250)
  const filtersPanel = useFiltersPanel('ksc-net-rules')
  const args = useMemo(
    () => ({ q: q || undefined, policy_id: policyId ?? filters.policy?.id, action: filters.action, direction: filters.direction, enabled: filters.enabled }),
    [q, policyId, filters],
  )
  const query = useNetRules(snapshotId, args)
  const pages = query.data?.pages ?? []
  const first = pages[0]
  const items = pages.flatMap((p) => p.items)
  const facets = first?.facets

  function set<K extends keyof Filters>(key: K, value: Filters[K]) { setFilters((prev) => ({ ...prev, [key]: value })) }
  function clearAll() { setFilters({}); setSearchInput('') }
  const chips: FilterChip[] = []
  if (!inPolicy && filters.policy) chips.push({ label: `политика ${filters.policy.name}`, clear: () => set('policy', undefined) })
  if (filters.action) chips.push({ label: `действие ${actionLabel(filters.action)}`, clear: () => set('action', undefined) })
  if (filters.direction) chips.push({ label: `направление ${directionLabel(filters.direction)}`, clear: () => set('direction', undefined) })
  if (filters.enabled !== undefined) chips.push({ label: filters.enabled ? 'включённые' : 'выключенные', clear: () => set('enabled', undefined) })
  const hasFilters = chips.length > 0 || q !== ''
  const errorMessage = query.error instanceof ApiRequestError ? query.error.message : query.isError ? 'Не удалось загрузить сетевые правила' : null
  const undescribed = first?.undescribed ?? []

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex shrink-0 flex-wrap items-center gap-3 border-b border-grid bg-surface px-4 py-2.5">
        <FiltersButton open={filtersPanel.open} onToggle={filtersPanel.toggle} count={chips.length} />
        <div className="relative max-w-sm flex-1">
          <Search size={14} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-text-secondary" aria-hidden />
          <input value={searchInput} onChange={(e) => setSearchInput(e.target.value)} placeholder="Название, адрес, порт" aria-label="Поиск сетевых правил" className="w-full rounded border border-border bg-app-bg py-1.5 pr-3 pl-8 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" />
        </div>
        {hasFilters && <button type="button" onClick={clearAll} className="flex items-center gap-1.5 rounded px-2 py-1 text-xs text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"><FilterX size={13} aria-hidden /> Сбросить</button>}
        <div className="font-mono text-xs tabular-nums text-text-secondary">{first ? first.total : '…'}</div>
        {!filtersPanel.open && <FilterChips chips={chips} />}
      </div>
      <div className="flex min-h-0 flex-1">
        {filtersPanel.open && (
          <FacetPanel total={first?.total ?? 0} noun="Правил">
            {!inPolicy && <PolicyFacet snapshotId={snapshotId} counts={facets?.policy} selected={filters.policy?.id} onSelect={(p) => set('policy', p)} />}
            <FacetSection title="Действие">
              {Object.entries(facets?.action ?? {}).map(([a, n]) => (
                <FacetRow key={a} active={filters.action === a} count={n} onClick={() => set('action', filters.action === a ? undefined : a)}>{actionLabel(a)}</FacetRow>
              ))}
            </FacetSection>
            <FacetSection title="Направление">
              {Object.entries(facets?.direction ?? {}).map(([d, n]) => (
                <FacetRow key={d} active={filters.direction === d} count={n} onClick={() => set('direction', filters.direction === d ? undefined : d)}>{directionLabel(d)}</FacetRow>
              ))}
            </FacetSection>
            <FacetSection title="Включено">
              {([true, false] as const).map((v) => (
                <FacetRow key={String(v)} active={filters.enabled === v} count={facets?.enabled[v ? 'true' : 'false']} onClick={() => set('enabled', filters.enabled === v ? undefined : v)}>{v ? 'включённые' : 'выключенные'}</FacetRow>
              ))}
            </FacetSection>
          </FacetPanel>
        )}
        <div className="min-w-0 flex-1 overflow-auto bg-app-bg">
          {query.isLoading && <FullPageSpinner />}
          {errorMessage && <div className="p-6"><ErrorState message={errorMessage} onRetry={() => query.refetch()} /></div>}
          {!query.isLoading && !errorMessage && (
            <>
              {!inPolicy && items.length > 0 && <UndescribedNote codes={undescribed} what="сетевые правила" />}
              {items.length === 0 ? (
                <ObjectsEmpty snapshotId={snapshotId} policyId={policyId} undescribed={undescribed} hasFilters={hasFilters} what="сетевые правила" none="Сетевых правил нет" nothing="Ни одно правило не подходит под фильтры." />
              ) : (
                <Rows items={items} inPolicy={inPolicy} />
              )}
              <LoadMore loaded={items.length} total={first?.total ?? 0} hasNext={!!query.hasNextPage} fetching={query.isFetchingNextPage} onMore={() => query.fetchNextPage()} />
            </>
          )}
        </div>
      </div>
    </div>
  )
}

export function NetRulesPage({ serverId }: { serverId: number }) {
  return <SnapshotSection serverId={serverId} title="Сетевые правила">{(sid) => <NetRulesTable snapshotId={sid} serverId={serverId} />}</SnapshotSection>
}
