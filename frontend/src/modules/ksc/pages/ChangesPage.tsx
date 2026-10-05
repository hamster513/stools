import { useMemo, useState } from 'react'
import { FilterX, History } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useChanges, useServers } from '@/modules/ksc/api/queries'
import {
  CHANGE_ACTION_LABELS,
  CHANGE_KIND_LABELS,
  CHANGE_KIND_PLURAL,
  EXCLUSION_KIND_LABELS,
  type ChangeAction,
  type ChangeItem,
  type ChangeKind,
  type ChangesSnapshot,
} from '@/modules/ksc/api/types'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { FiltersButton, FilterChips, type FilterChip } from '@/platform/filters/FiltersBar'
import { useFiltersPanel } from '@/platform/filters/useFiltersPanel'
import { FacetPanel, FacetRow, FacetSection } from './policies/Facets'
import { LoadMore, PolicyCell, PolicyFacet } from './objects/ObjectsParts'
import { ChangeValue } from './changes/ChangeValue'

interface Filters {
  kind?: ChangeKind
  action?: ChangeAction
  policy?: { id: number; name: string }
  snapshot?: number
}

/** Поля политики и профиля, которые журнал пишет в `path`. */
const FIELD_LABELS: Record<string, string> = {
  name: 'название',
  active: 'активность',
  group: 'группа',
  accept_parent: 'принимать родительскую',
  enabled: 'включён',
  priority: 'приоритет',
  condition: 'условие',
}

function when(iso: string): string {
  return new Date(iso).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' })
}

/** Запись извлекателя (исключение, сетевое правило) — сама запись, а не её ключ: `<вид>: <значение>` или имя правила. */
function isRecord(c: ChangeItem): boolean {
  return c.kind === 'exclusion' || c.kind === 'net_rule'
}

function where(c: ChangeItem): string {
  const record = c.after ?? c.before
  if (isRecord(c) && typeof record === 'object' && record !== null) {
    const r = record as Record<string, unknown>
    const text = c.kind === 'exclusion' ? `${EXCLUSION_KIND_LABELS[String(r.kind)] ?? String(r.kind)}: ${String(r.value ?? '')}` : String(r.name ?? '')
    return text || '—'
  }
  const path = c.kind === 'policy' || c.kind === 'profile' ? (FIELD_LABELS[c.path] ?? c.path) : c.path
  return [c.section, path].filter(Boolean).join(' · ') || '—'
}

/** Строка о снапшоте: с чем сравнивали, что не сравнивалось и почему, обрезан ли список. */
function SnapshotLine({ snap, all, inPolicy }: { snap: ChangesSnapshot; all: ChangesSnapshot[]; inPolicy: boolean }) {
  const prev = snap.prev !== null ? all.find((s) => s.id === snap.prev) : undefined
  const notCompared = (Object.entries(snap.compared) as [ChangeKind, boolean][]).filter(([, v]) => !v).map(([k]) => CHANGE_KIND_PLURAL[k] ?? k)
  const parts: string[] = []
  if (snap.total === null) parts.push(snap.reason ?? 'изменения не считались — пересчитайте снапшот')
  else if (snap.prev === null) parts.push('первый снапшот — сравнивать не с чем')
  else {
    // В карточке политики число по всему серверу сбивало бы с толку — оно только в разделе «Изменения».
    parts.push(`сравнение с #${snap.prev}${prev ? ` от ${when(prev.collected_at)}` : ''}${inPolicy ? '' : `, изменений ${snap.total}`}`)
    if (snap.reason) parts.push(snap.reason)
    if (notCompared.length) parts.push(`не сравнивались: ${notCompared.join(', ')} (не собрано в одном из снапшотов или продукт не описан)`)
    if (snap.truncated) parts.push(`список обрезан до ${snap.total} записей`)
  }
  return (
    <div className="border-b border-grid bg-surface px-4 py-2 text-xs text-text-secondary">
      Снапшот #{snap.id} от {when(snap.collected_at)}: {parts.join('; ')}.
    </div>
  )
}

function Rows({ items, inPolicy }: { items: ChangeItem[]; inPolicy: boolean }) {
  return (
    <div className="min-w-[1240px]">
      <div className="sticky top-0 z-10 flex border-b border-grid bg-surface text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
        <div className="w-36 shrink-0 px-2 py-2">Сбор</div>
        <div className="w-36 shrink-0 px-2 py-2">Вид</div>
        <div className="w-24 shrink-0 px-2 py-2">Действие</div>
        <div className="w-56 shrink-0 px-2 py-2">{inPolicy ? 'Профиль' : 'Политика / профиль'}</div>
        <div className="w-72 shrink-0 px-2 py-2">Где</div>
        <div className="min-w-[280px] flex-1 px-2 py-2">Значение</div>
      </div>
      {items.map((c) => (
        <div key={c.id} className="flex items-start border-b border-grid py-2 text-xs">
          <div className="w-36 shrink-0 px-2 text-text-secondary">{when(c.collected_at)}</div>
          <div className="w-36 shrink-0 px-2 text-text">{CHANGE_KIND_LABELS[c.kind] ?? c.kind}</div>
          <div className="w-24 shrink-0 px-2 text-text-secondary">{CHANGE_ACTION_LABELS[c.action] ?? c.action}</div>
          <div className="w-56 shrink-0 px-2"><PolicyCell policyName={c.policy_name} profile={c.profile} inPolicy={inPolicy} /></div>
          <div className="w-72 shrink-0 px-2 font-mono break-all text-text-secondary" title={isRecord(c) ? `ключ ${c.path}` : undefined}>{where(c)}</div>
          <div className="min-w-[280px] flex-1 px-2"><ChangeValue kind={c.kind} before={c.before} after={c.after} /></div>
        </div>
      ))}
    </div>
  )
}

/** Пустой журнал: «сравнивать не с чем» и «не считались» отличаются от «изменений нет». */
function Empty({ snapshots, hasFilters }: { snapshots: ChangesSnapshot[]; hasFilters: boolean }) {
  let body
  if (hasFilters) body = <EmptyState icon={FilterX} title="Ничего не найдено" description="Ни одна запись журнала не подходит под фильтры." />
  else if (snapshots.length === 0) body = <EmptyState icon={History} title="Снапшотов нет" description="Загрузите выгрузку или запустите сбор из KSC в настройках модуля." />
  else if (!snapshots.some((s) => s.prev !== null && s.total !== null)) {
    const uncounted = snapshots.some((s) => s.total === null)
    body = (
      <EmptyState icon={History} title="Сравнивать не с чем" description={uncounted
        ? 'Изменения не считались — пересчитайте снапшоты на экране «Снапшоты».'
        : 'Есть только первый снапшот сервера: изменения появятся после следующего сбора.'} />
    )
  } else body = <EmptyState icon={History} title="Изменений нет" description="В сравнённых снапшотах изменений не найдено. Что не сравнивалось — в строке выше." />
  return <div className="p-6">{body}</div>
}

/** Журнал изменений сервера: от новых к старым, фильтры чипами. С `policyId` — по одной политике, с `snapshotId` — по одному снапшоту. */
export function ChangesList({ serverId, policyId, snapshotId }: { serverId: number; policyId?: number; snapshotId?: number }) {
  const inPolicy = policyId !== undefined
  const servers = useServers()
  const latestId = servers.data?.find((s) => s.id === serverId)?.last_snapshot_id ?? undefined
  const [filters, setFilters] = useState<Filters>({})
  const filtersPanel = useFiltersPanel('ksc-changes')
  const args = useMemo(
    () => ({ kind: filters.kind, action: filters.action, policy_id: policyId ?? filters.policy?.id, snapshot_id: snapshotId ?? filters.snapshot }),
    [filters, policyId, snapshotId],
  )
  const query = useChanges(serverId, args)
  const pages = query.data?.pages ?? []
  const first = pages[0]
  const items = pages.flatMap((p) => p.items)
  const facets = first?.facets
  const snapshots = first?.snapshots ?? []
  const shown = snapshotId ?? filters.snapshot
  const current = (shown !== undefined ? snapshots.find((s) => s.id === shown) : undefined) ?? snapshots[0]

  function set<K extends keyof Filters>(key: K, value: Filters[K]) { setFilters((prev) => ({ ...prev, [key]: value })) }
  const chips: FilterChip[] = []
  if (filters.kind) chips.push({ label: `вид ${CHANGE_KIND_LABELS[filters.kind]}`, clear: () => set('kind', undefined) })
  if (filters.action) chips.push({ label: CHANGE_ACTION_LABELS[filters.action], clear: () => set('action', undefined) })
  if (!inPolicy && filters.policy) chips.push({ label: `политика ${filters.policy.name}`, clear: () => set('policy', undefined) })
  if (snapshotId === undefined && filters.snapshot !== undefined) chips.push({ label: `снапшот #${filters.snapshot}`, clear: () => set('snapshot', undefined) })
  const errorMessage = query.error instanceof ApiRequestError ? query.error.message : query.isError ? 'Не удалось загрузить журнал изменений' : null

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex shrink-0 flex-wrap items-center gap-3 border-b border-grid bg-surface px-4 py-2.5">
        <FiltersButton open={filtersPanel.open} onToggle={filtersPanel.toggle} count={chips.length} />
        {chips.length > 0 && <button type="button" onClick={() => setFilters({})} className="flex items-center gap-1.5 rounded px-2 py-1 text-xs text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"><FilterX size={13} aria-hidden /> Сбросить</button>}
        <div className="font-mono text-xs tabular-nums text-text-secondary">{first ? first.total : '…'}</div>
        {!filtersPanel.open && <FilterChips chips={chips} />}
      </div>
      {current && <SnapshotLine snap={current} all={snapshots} inPolicy={inPolicy} />}
      <div className="flex min-h-0 flex-1">
        {filtersPanel.open && (
          <FacetPanel total={first?.total ?? 0} noun="Записей">
            <FacetSection title="Вид">
              {(Object.entries(facets?.kind ?? {}) as [ChangeKind, number][]).map(([k, n]) => (
                <FacetRow key={k} active={filters.kind === k} count={n} onClick={() => set('kind', filters.kind === k ? undefined : k)}>{CHANGE_KIND_LABELS[k] ?? k}</FacetRow>
              ))}
            </FacetSection>
            <FacetSection title="Действие">
              {(Object.entries(facets?.action ?? {}) as [ChangeAction, number][]).map(([a, n]) => (
                <FacetRow key={a} active={filters.action === a} count={n} onClick={() => set('action', filters.action === a ? undefined : a)}>{CHANGE_ACTION_LABELS[a] ?? a}</FacetRow>
              ))}
            </FacetSection>
            {!inPolicy && <PolicyFacet snapshotId={latestId} selected={filters.policy?.id} onSelect={(p) => set('policy', p)} />}
            {snapshotId === undefined && (
              <FacetSection title="Снапшот">
                {snapshots.map((s) => (
                  <FacetRow key={s.id} active={filters.snapshot === s.id} count={inPolicy ? undefined : (s.total ?? undefined)} onClick={() => set('snapshot', filters.snapshot === s.id ? undefined : s.id)}>
                    #{s.id} · {when(s.collected_at)}{s.total === null ? ' · не считались' : s.prev === null ? ' · первый' : ''}
                  </FacetRow>
                ))}
              </FacetSection>
            )}
          </FacetPanel>
        )}
        <div className="min-w-0 flex-1 overflow-auto bg-app-bg">
          {query.isLoading && <FullPageSpinner />}
          {errorMessage && <div className="p-6"><ErrorState message={errorMessage} onRetry={() => query.refetch()} /></div>}
          {!query.isLoading && !errorMessage && (
            <>
              {items.length === 0 ? <Empty snapshots={snapshots} hasFilters={chips.length > 0} /> : <Rows items={items} inPolicy={inPolicy} />}
              <LoadMore loaded={items.length} total={first?.total ?? 0} hasNext={!!query.hasNextPage} fetching={query.isFetchingNextPage} onMore={() => query.fetchNextPage()} />
            </>
          )}
        </div>
      </div>
    </div>
  )
}

export function ChangesPage({ serverId }: { serverId: number }) {
  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex shrink-0 items-baseline gap-3 border-b border-grid bg-surface px-4 py-2.5">
        <h1 className="text-sm font-semibold text-text">Изменения</h1>
        <span className="text-xs text-text-secondary">разница между соседними сборами, от новых к старым</span>
      </header>
      <div className="min-h-0 flex-1"><ChangesList serverId={serverId} /></div>
    </div>
  )
}
