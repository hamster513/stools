import { useCallback, useId, useMemo, useState } from 'react'
import { FilterX, Search } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useRouter } from '@/lib/router'
import { useHostDetail, useNetRuleSections, useNetRuleSummary } from '@/modules/ksc/api/queries'
import type { NetRulesQuery } from '@/modules/ksc/api/types'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { ExportButton } from '@/platform/filters/ExportButton'
import { exportHref } from '@/platform/filters/exportHref'
import { FiltersButton, FilterChips, type FilterChip } from '@/platform/filters/FiltersBar'
import { facetValues, useRememberedFacets } from '@/platform/filters/useRememberedFacets'
import { toggleValue, toWire, valueChips } from '@/platform/findings/facets'
import { useFiltersPanel } from '@/platform/filters/useFiltersPanel'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { FacetPanel, FacetRow, FacetSection } from './policies/Facets'
import { ObjectDrawer } from './objects/ObjectDrawer'
import { ObjectsEmpty, PartialNote, PartialPoliciesNote, PolicyFacet, SnapshotSection, UndescribedNote, UndeterminedNote } from './objects/ObjectsParts'
import { HostPicker } from './netrules/HostPicker'
import { FirewallCheckPanel } from './netrules/FirewallCheckPanel'
import { SectionTable } from './netrules/SectionTable'
import { mergeSections, MODE_LABELS, readFilters, writeFilters, type Filters } from './netrules/model'

export function NetRulesTable({ snapshotId, serverId, policyId, partial = false, hostId, policyIds, syncUrl = false }: { snapshotId: number; serverId: number; policyId?: number; partial?: boolean; hostId?: string; policyIds?: number[]; syncUrl?: boolean }) {
  const inPolicy = policyId !== undefined
  const checkId = useId()
  const [checkOpen, setCheckOpen] = useState(false)
  const router = useRouter()
  const [localFilters, setLocalFilters] = useState<Filters>({})
  const filters = useMemo(() => syncUrl ? readFilters(router.search) : localFilters, [syncUrl, router.search, localFilters])
  const selectedHost = hostId ?? filters.host_id
  const selectionScope = JSON.stringify([snapshotId, policyId, selectedHost])
  const [selection, setSelection] = useState<{ scope: string; id: number } | null>(null)
  const openRowId = selection?.scope === selectionScope ? selection.id : null
  const setOpenRowId = (id: number) => setSelection({ scope: selectionScope, id })
  const closeRow = useCallback(() => setSelection(null), [])
  const q = useDebouncedValue(filters.q ?? '', 250)
  const selectedHostDetail = useHostDetail(snapshotId, selectedHost)
  const filtersPanel = useFiltersPanel('ksc-net-rules')
  const baseArgs = useMemo<NetRulesQuery>(() => ({ policy_id: policyId === undefined ? undefined : [policyId], host_id: selectedHost }), [policyId, selectedHost])
  const args = useMemo<NetRulesQuery>(() => ({ ...baseArgs, q: q || undefined, policy_id: baseArgs.policy_id ?? filters.policy_id, action: toWire(filters.action), direction: toWire(filters.direction), enabled: filters.enabled }), [baseArgs, q, filters])
  const baseline = useNetRuleSections(snapshotId, baseArgs)
  const filtered = useNetRuleSections(snapshotId, args)
  // Метаданные и фасеты без загрузки строк всех секций.
  const summary = useNetRuleSummary(snapshotId, args)
  const first = summary.data
  const sections = useMemo(() => mergeSections(baseline.data ?? [], filtered.data ?? []), [baseline.data, filtered.data])
  const facets = first?.facets
  const remembered = useRememberedFacets(facets ? { action: facetValues(facets.action, false), direction: facetValues(facets.direction, false), policy: facetValues(facets.policy, false) } : undefined)
  function update(patch: Partial<Filters>) {
    const next = { ...filters, ...patch }
    if (patch.host_id !== filters.host_id && 'host_id' in patch) closeRow()
    if (syncUrl) { const search = writeFilters(router.search, next); router.navigate(`${router.path}${search ? `?${search}` : ''}`, { replace: true }) }
    else setLocalFilters(next)
  }
  function clearAll() { update({ q: undefined, action: undefined, direction: undefined, policy_id: undefined, enabled: undefined, host_id: undefined }) }
  const names = new Map(baseline.data?.map(s => [s.policy_id, s.policy_name]))
  const chips: FilterChip[] = []
  if (!inPolicy) chips.push(...(filters.policy_id ?? []).map(id => ({ label: `Политика: ${names.get(id) || `#${id}`}`, clear: () => update({ policy_id: toggleValue(filters.policy_id, id) }) })))
  chips.push(...valueChips('Действие', filters.action, v => v || '—', v => update({ action: v })))
  chips.push(...valueChips('Направление', filters.direction, v => v || '—', v => update({ direction: v })))
  if (filters.enabled !== undefined) chips.push({ label: filters.enabled ? 'включённые' : 'выключенные', clear: () => update({ enabled: undefined }) })
  const hasFilters = chips.length > 0 || q !== ''
  const failed = [baseline, filtered, summary].find(query => query.isError)
  const errorMessage = failed?.error instanceof ApiRequestError ? failed.error.message : failed ? 'Не удалось загрузить сетевые правила' : null
  const loading = baseline.isLoading || filtered.isLoading || summary.isLoading
  const partialIds = useMemo(() => {
    const all = first?.partial ?? []
    if (!selectedHost) return all
    const ids = policyIds ?? selectedHostDetail.data?.policies.map(p => p.id)
    if (!ids) return all
    const own = new Set(ids)
    return all.filter(id => own.has(id))
  }, [first, selectedHost, policyIds, selectedHostDetail.data])
  const maybe = useMemo(() => new Set((first?.undetermined ?? []).map(u => `${u.policy_id}\u0000${u.profile}`)), [first])
  const scopeKey = `${snapshotId}:${policyId ?? 'all'}:${selectedHost ?? 'all'}`

  return <div className="flex h-full min-h-0 flex-col">
    <div className="flex shrink-0 flex-wrap items-center gap-3 border-b border-grid bg-surface px-4 py-2.5">
      <FiltersButton open={filtersPanel.open} onToggle={filtersPanel.toggle} count={chips.length} />
      <button type="button" aria-expanded={checkOpen} aria-controls={checkId} onClick={() => setCheckOpen(v => !v)} className="rounded border border-border px-2 py-1.5 text-xs text-primary hover:bg-row-hover focus-visible:ring-2 focus-visible:ring-focus-ring">Проверить связь</button>
      <ExportButton href={exportHref(`/api/ksc/snapshots/${snapshotId}/net-rules/export`, args)} total={first?.total} disabled={loading} />
      {!inPolicy && hostId === undefined && <HostPicker snapshotId={snapshotId} value={selectedHost} onChange={id => update({ host_id: id })} />}
      <div className="relative max-w-sm min-w-40 flex-1">
        <Search size={14} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-text-secondary" aria-hidden />
        <input value={filters.q ?? ''} onChange={e => update({ q: e.target.value || undefined })} placeholder="Название, адрес, порт" aria-label="Поиск сетевых правил" className="w-full rounded border border-border bg-app-bg py-1.5 pr-3 pl-8 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" />
      </div>
      {(hasFilters || (hostId === undefined && selectedHost)) && <button type="button" onClick={clearAll} className="flex items-center gap-1.5 rounded px-2 py-1 text-xs text-text-secondary hover:bg-row-hover hover:text-text focus-visible:ring-2 focus-visible:ring-focus-ring"><FilterX size={13} aria-hidden /> Сбросить</button>}
      <div className="font-mono text-xs tabular-nums text-text-secondary">{first?.total ?? '…'} записей в источниках</div>
      {!filtersPanel.open && <FilterChips chips={chips} />}
    </div>
    <div className="flex min-h-0 flex-1">
      {filtersPanel.open && <FacetPanel total={first?.total ?? 0} noun="Правил">
        {!inPolicy && <PolicyFacet snapshotId={snapshotId} counts={remembered.policy} selected={filters.policy_id} onToggle={p => update({ policy_id: toggleValue(filters.policy_id, p.id) })} />}
        <FacetSection title="Действие">{(remembered.action ?? []).map(({ value, count }) => <FacetRow key={value} active={filters.action?.includes(value) ?? false} count={count} onClick={() => update({ action: toggleValue(filters.action, value) })}>{value || '—'}</FacetRow>)}</FacetSection>
        <FacetSection title="Направление">{(remembered.direction ?? []).map(({ value, count }) => <FacetRow key={value} active={filters.direction?.includes(value) ?? false} count={count} onClick={() => update({ direction: toggleValue(filters.direction, value) })}>{value || '—'}</FacetRow>)}</FacetSection>
        <FacetSection title="Включено">{([true, false] as const).map(v => <FacetRow key={String(v)} active={filters.enabled === v} count={facets?.enabled[v ? 'true' : 'false']} onClick={() => update({ enabled: filters.enabled === v ? undefined : v })}>{v ? 'включённые' : 'выключенные'}</FacetRow>)}</FacetSection>
      </FacetPanel>}
      <div className="min-w-0 flex-1 overflow-auto bg-app-bg">
        {checkOpen && <FirewallCheckPanel key={scopeKey} id={checkId} snapshotId={snapshotId} serverId={serverId} initialHost={selectedHost} onOpenRule={setOpenRowId} onClose={() => setCheckOpen(false)} />}
        {loading && <FullPageSpinner />}
        {errorMessage && <div className="p-6"><ErrorState message={errorMessage} onRetry={() => { baseline.refetch(); filtered.refetch(); summary.refetch() }} /></div>}
        {!loading && !errorMessage && <>
          {!inPolicy && <UndescribedNote codes={first?.undescribed ?? []} what="сетевые правила" />}
          <UndeterminedNote items={first?.undetermined ?? []} />
          {inPolicy ? partial && <PartialNote bar /> : <PartialPoliciesNote snapshotId={snapshotId} ids={partialIds} />}
          {selectedHost && first?.effective && <div className="border-b border-grid px-4 py-2 text-xs text-text-secondary">Режим наложения профилей: {MODE_LABELS[first.effective.mode]}. Причина неактивности указана у каждого набора.</div>}
          {sections.length === 0 ? <ObjectsEmpty snapshotId={snapshotId} policyId={policyId} undescribed={first?.undescribed ?? []} hasFilters={hasFilters} what="сетевые правила" none={selectedHost ? 'Для хоста нет собранных сетевых правил' : 'Сетевых правил нет'} nothing="Ни одно правило не подходит под фильтры." /> : <>
            {first?.total === 0 && <p className="border-b border-grid px-4 py-3 text-xs text-text-secondary">Ни одно правило не подходит под фильтры. Секции сохранены для сравнения.</p>}
            <SectionTable key={scopeKey} storageKey={`ksc-net-rules-sections-v3:${scopeKey}`} snapshotId={snapshotId} sections={sections} args={args} openRowId={openRowId} onOpen={setOpenRowId} maybe={maybe} />
          </>}
        </>}
      </div>
    </div>
    <ObjectDrawer kind="net_rule" rowId={openRowId} snapshotId={snapshotId} serverId={serverId} onOpen={setOpenRowId} onClose={closeRow} />
  </div>
}

export function NetRulesPage({ serverId }: { serverId: number }) {
  return <SnapshotSection serverId={serverId} title="Сетевые правила">{sid => <NetRulesTable key={sid} snapshotId={sid} serverId={serverId} syncUrl />}</SnapshotSection>
}
