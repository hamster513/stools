import { useMemo, useState } from 'react'
import { FilterX, Search } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useExclusions } from '@/modules/ksc/api/queries'
import {
  EXCLUSION_DUP_LABELS,
  EXCLUSION_KIND_LABELS,
  type ExclusionDup,
  type ExclusionItem,
  type ExclusionSummaryItem,
} from '@/modules/ksc/api/types'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { FiltersButton, FilterChips, type FilterChip } from '@/platform/filters/FiltersBar'
import { useFiltersPanel } from '@/platform/filters/useFiltersPanel'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { FacetPanel, FacetRow, FacetSection } from './policies/Facets'
import { LoadMore, ObjectsEmpty, PartialNote, PolicyCell, PolicyFacet, RiskChips, SnapshotSection, UndescribedNote } from './objects/ObjectsParts'

interface Filters {
  policy?: { id: number; name: string }
  kind?: string
  enabled?: boolean
  dup?: ExclusionDup
  risky?: boolean
}

const kindLabel = (k: string) => EXCLUSION_KIND_LABELS[k] ?? k

/** Сводка по политикам — без фильтров; имя политики ставит фильтр по ней. Неполное содержимое помечено у имени. */
function Summary({ items, onPick }: { items: ExclusionSummaryItem[]; onPick: (p: { id: number; name: string }) => void }) {
  const kinds = [...new Set(items.flatMap((s) => Object.keys(s.by_kind)))].sort()
  return (
    <details className="m-4 rounded border border-grid bg-surface">
      <summary className="cursor-pointer px-3 py-2 text-xs font-semibold text-text select-none">
        Сводка по политикам <span className="font-normal text-text-secondary">— {items.length}</span>
      </summary>
      <div className="overflow-x-auto px-3 pb-3">
        <table className="w-full text-xs">
          <thead className="text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
            <tr>
              <th className="py-1 pr-3 text-left">Политика</th>
              <th className="py-1 pr-3 text-right">Хостов</th>
              <th className="py-1 pr-3 text-right">Всего</th>
              <th className="py-1 pr-3 text-right">Опасных</th>
              {kinds.map((k) => <th key={k} className="py-1 pr-3 text-right">{kindLabel(k)}</th>)}
            </tr>
          </thead>
          <tbody>
            {items.map((s) => (
              <tr key={s.policy_id} className="border-t border-grid">
                <td className="py-1.5 pr-3">
                  <button type="button" onClick={() => onPick({ id: s.policy_id, name: s.policy_name })} className="text-left text-text hover:text-primary">{s.policy_name}</button>
                  {s.partial && <span className="ml-2 whitespace-nowrap text-risk-medium" title="содержимое политики собрано не полностью — список может быть неполным">собрано не полностью</span>}
                </td>
                <td className="py-1.5 pr-3 text-right font-mono tabular-nums text-text-secondary">{s.hosts}</td>
                <td className="py-1.5 pr-3 text-right font-mono tabular-nums text-text">{s.total}</td>
                <td className={s.risky > 0 ? 'py-1.5 pr-3 text-right font-mono tabular-nums text-risk-high' : 'py-1.5 pr-3 text-right font-mono tabular-nums text-text-secondary'}>{s.risky}</td>
                {kinds.map((k) => <td key={k} className="py-1.5 pr-3 text-right font-mono tabular-nums text-text-secondary">{s.by_kind[k] ?? 0}</td>)}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  )
}

function Rows({ items, inPolicy }: { items: ExclusionItem[]; inPolicy: boolean }) {
  return (
    <div className="min-w-[1536px]">
      <div className="sticky top-0 z-10 flex border-b border-grid bg-surface text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
        <div className="min-w-[240px] flex-1 px-2 py-2">Значение</div>
        <div className="w-44 shrink-0 px-2 py-2">Риск</div>
        <div className="w-24 shrink-0 px-2 py-2">Вид</div>
        <div className="w-56 shrink-0 px-2 py-2">{inPolicy ? 'Профиль' : 'Политика / профиль'}</div>
        <div className="w-48 shrink-0 px-2 py-2">Компоненты</div>
        <div className="w-20 shrink-0 px-2 py-2">Включено</div>
        <div className="w-56 shrink-0 px-2 py-2">Комментарий</div>
        <div className="w-28 shrink-0 px-2 py-2">Политик</div>
        <div className="w-48 shrink-0 px-2 py-2">Перекрыто</div>
      </div>
      {items.map((e) => (
        <div key={e.id} className="flex items-start border-b border-grid py-2 text-xs">
          <div className="min-w-[240px] flex-1 px-2 font-mono break-all text-text">{e.value}</div>
          <div className="w-44 shrink-0 px-2"><RiskChips risks={e.risks} titles={e.risk_titles} /></div>
          <div className="w-24 shrink-0 px-2 text-text-secondary">{kindLabel(e.kind)}</div>
          <div className="w-56 shrink-0 px-2"><PolicyCell policyName={e.policy_name} profile={e.profile} inPolicy={inPolicy} /></div>
          <div className="w-48 shrink-0 px-2 text-text-secondary">{e.components.length ? e.components.join(', ') : '—'}</div>
          <div className="w-20 shrink-0 px-2 text-text-secondary">{e.enabled ? 'да' : 'нет'}</div>
          <div className="w-56 shrink-0 px-2 break-words text-text-secondary">{e.comment || '—'}</div>
          <div className={e.policies > 1 ? 'w-28 shrink-0 px-2 text-risk-medium' : 'w-28 shrink-0 px-2 text-text-secondary'}>в {e.policies}</div>
          <div className="w-48 shrink-0 px-2 font-mono break-all text-text-secondary">{e.covered_by ?? '—'}</div>
        </div>
      ))}
    </div>
  )
}

/**
 * Исключения снапшота: поиск, фильтры чипами, сводка, таблица. С `policyId` — по одной политике, без фильтра политики и сводки;
 * `partial` — её содержимое собрано не полностью.
 */
export function ExclusionsTable({ snapshotId, policyId, partial = false }: { snapshotId: number; serverId: number; policyId?: number; partial?: boolean }) {
  const inPolicy = policyId !== undefined
  const [filters, setFilters] = useState<Filters>({})
  const [searchInput, setSearchInput] = useState('')
  const q = useDebouncedValue(searchInput, 250)
  const filtersPanel = useFiltersPanel('ksc-exclusions')
  const args = useMemo(
    () => ({ q: q || undefined, policy_id: policyId ?? filters.policy?.id, kind: filters.kind, enabled: filters.enabled, dup: filters.dup, risky: filters.risky }),
    [q, policyId, filters],
  )
  const query = useExclusions(snapshotId, args)
  const pages = query.data?.pages ?? []
  const first = pages[0]
  const items = pages.flatMap((p) => p.items)
  const facets = first?.facets

  function set<K extends keyof Filters>(key: K, value: Filters[K]) { setFilters((prev) => ({ ...prev, [key]: value })) }
  function clearAll() { setFilters({}); setSearchInput('') }
  const chips: FilterChip[] = []
  if (!inPolicy && filters.policy) chips.push({ label: `политика ${filters.policy.name}`, clear: () => set('policy', undefined) })
  if (filters.kind) chips.push({ label: `вид ${kindLabel(filters.kind)}`, clear: () => set('kind', undefined) })
  if (filters.enabled !== undefined) chips.push({ label: filters.enabled ? 'включённые' : 'выключенные', clear: () => set('enabled', undefined) })
  if (filters.dup) chips.push({ label: EXCLUSION_DUP_LABELS[filters.dup], clear: () => set('dup', undefined) })
  if (filters.risky !== undefined) chips.push({ label: filters.risky ? 'опасные' : 'без риска', clear: () => set('risky', undefined) })
  const hasFilters = chips.length > 0 || q !== ''
  const errorMessage = query.error instanceof ApiRequestError ? query.error.message : query.isError ? 'Не удалось загрузить исключения' : null
  const undescribed = first?.undescribed ?? []

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex shrink-0 flex-wrap items-center gap-3 border-b border-grid bg-surface px-4 py-2.5">
        <FiltersButton open={filtersPanel.open} onToggle={filtersPanel.toggle} count={chips.length} />
        <div className="relative max-w-sm flex-1">
          <Search size={14} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-text-secondary" aria-hidden />
          <input value={searchInput} onChange={(e) => setSearchInput(e.target.value)} placeholder={inPolicy ? 'Значение, комментарий' : 'Значение, комментарий, политика'} aria-label="Поиск исключений" className="w-full rounded border border-border bg-app-bg py-1.5 pr-3 pl-8 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" />
        </div>
        {hasFilters && <button type="button" onClick={clearAll} className="flex items-center gap-1.5 rounded px-2 py-1 text-xs text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"><FilterX size={13} aria-hidden /> Сбросить</button>}
        <div className="font-mono text-xs tabular-nums text-text-secondary">{first ? first.total : '…'}</div>
        {!filtersPanel.open && <FilterChips chips={chips} />}
      </div>
      <div className="flex min-h-0 flex-1">
        {filtersPanel.open && (
          <FacetPanel total={first?.total ?? 0} noun="Исключений">
            {!inPolicy && <PolicyFacet snapshotId={snapshotId} counts={facets?.policy} selected={filters.policy?.id} onSelect={(p) => set('policy', p)} />}
            <FacetSection title="Риск">
              {([true, false] as const).map((v) => (
                <FacetRow key={String(v)} active={filters.risky === v} count={facets?.risky?.[v ? 'true' : 'false']} onClick={() => set('risky', filters.risky === v ? undefined : v)}>{v ? 'опасные' : 'без риска'}</FacetRow>
              ))}
            </FacetSection>
            <FacetSection title="Вид">
              {Object.entries(facets?.kind ?? {}).map(([k, n]) => (
                <FacetRow key={k} active={filters.kind === k} count={n} onClick={() => set('kind', filters.kind === k ? undefined : k)}>{kindLabel(k)}</FacetRow>
              ))}
            </FacetSection>
            <FacetSection title="Включено">
              {([true, false] as const).map((v) => (
                <FacetRow key={String(v)} active={filters.enabled === v} count={facets?.enabled[v ? 'true' : 'false']} onClick={() => set('enabled', filters.enabled === v ? undefined : v)}>{v ? 'включённые' : 'выключенные'}</FacetRow>
              ))}
            </FacetSection>
            <FacetSection title="Дубли и перекрытия">
              {(Object.keys(EXCLUSION_DUP_LABELS) as ExclusionDup[]).map((d) => (
                <FacetRow key={d} active={filters.dup === d} count={facets?.dup[d]} onClick={() => set('dup', filters.dup === d ? undefined : d)}>{EXCLUSION_DUP_LABELS[d]}</FacetRow>
              ))}
            </FacetSection>
          </FacetPanel>
        )}
        <div className="min-w-0 flex-1 overflow-auto bg-app-bg">
          {query.isLoading && <FullPageSpinner />}
          {errorMessage && <div className="p-6"><ErrorState message={errorMessage} onRetry={() => query.refetch()} /></div>}
          {!query.isLoading && !errorMessage && (
            <>
              {!inPolicy && items.length > 0 && <UndescribedNote codes={undescribed} what="исключения" />}
              {inPolicy ? partial && <PartialNote bar /> : <PartialNote bar names={(first?.summary ?? []).filter((s) => s.partial).map((s) => s.policy_name)} />}
              {!inPolicy && first?.summary && first.summary.length > 0 && <Summary items={first.summary} onPick={(p) => set('policy', p)} />}
              {items.length === 0 ? (
                <ObjectsEmpty snapshotId={snapshotId} policyId={policyId} undescribed={undescribed} hasFilters={hasFilters} what="исключения" none="Исключений нет" nothing="Ни одно исключение не подходит под фильтры." />
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

export function ExclusionsPage({ serverId }: { serverId: number }) {
  return <SnapshotSection serverId={serverId} title="Исключения">{(sid) => <ExclusionsTable snapshotId={sid} serverId={serverId} />}</SnapshotSection>
}
