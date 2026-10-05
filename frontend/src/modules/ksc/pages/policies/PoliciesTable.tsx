import { useMemo, useState } from 'react'
import { ChevronRight, FilterX, Search } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { usePolicyList } from '@/modules/ksc/api/queries'
import { GRADE_LABELS, type PolicyGrade, type PolicyListItem, type PolicyListQuery } from '@/modules/ksc/api/types'
import { clickableRow, ROW_FOCUS } from '@/components/ui/clickableRow'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { FiltersButton, FilterChips, type FilterChip } from '@/platform/filters/FiltersBar'
import { useFiltersPanel } from '@/platform/filters/useFiltersPanel'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { Link, useRouter } from '@/lib/router'
import { cn } from '@/lib/cn'
import { FacetPanel, FacetRow, FacetSection } from './Facets'
import { GradeBadge } from './GradeBadge'

type PolicyFilters = Pick<PolicyListQuery, 'product' | 'active' | 'grade'>

const GRADE_FILTERS: (PolicyGrade | 'none')[] = ['bad', 'ok', 'good', 'none']
const gradeLabel = (g: PolicyGrade | 'none') => (g === 'none' ? 'нет оценки' : GRADE_LABELS[g])

function LocksCell({ p }: { p: PolicyListItem }) {
  if (!p.locks) return <span className="text-text-secondary" title="содержимое не собрано">—</span>
  if (p.locks.with_lock_flag === 0) return <span className="text-text-secondary">не распознаны</span>
  return <span className="font-mono tabular-nums text-text-secondary">{p.locks.locked} из {p.locks.with_lock_flag}</span>
}

/** Исключения: «—», если считать не из чего (нет содержимого или продукт не описан), а не «0». */
function ExclusionsCell({ p }: { p: PolicyListItem }) {
  if (!p.has_contents) return <span className="text-text-secondary" title="содержимое не собрано">—</span>
  if (!p.described) return <span className="text-text-secondary" title="продукт не описан">—</span>
  return <span className="font-mono tabular-nums text-text-secondary">{p.exclusions}</span>
}

function Table({ items, serverId }: { items: PolicyListItem[]; serverId: number }) {
  const { navigate } = useRouter()
  return (
    <div className="h-full overflow-auto">
      <div className="sticky top-0 z-10 flex min-w-[1320px] border-b border-grid bg-surface text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
        <div className="min-w-[240px] flex-1 px-2 py-2">Политика</div>
        <div className="w-40 shrink-0 px-2 py-2">Продукт</div>
        <div className="w-48 shrink-0 px-2 py-2">Группа</div>
        <div className="w-20 shrink-0 px-2 py-2">Активна</div>
        <div className="w-16 shrink-0 px-2 py-2 text-right">Групп</div>
        <div className="w-16 shrink-0 px-2 py-2 text-right">Хостов</div>
        <div className="w-28 shrink-0 px-2 py-2">Оценка</div>
        <div className="w-28 shrink-0 px-2 py-2">Замки</div>
        <div className="w-24 shrink-0 px-2 py-2 text-right">Профилей</div>
        <div className="w-24 shrink-0 px-2 py-2 text-right">Исключений</div>
        <div className="w-20 shrink-0 px-2 py-2 text-right">Находок</div>
        <div className="w-6 shrink-0" />
      </div>
      {items.map((p) => (
        <div key={p.id} {...clickableRow(() => navigate(`/ksc/servers/${serverId}/policies/${p.id}`))} className={cn(ROW_FOCUS, 'flex min-w-[1320px] cursor-pointer items-center border-b border-grid py-2 text-xs hover:bg-row-hover')}>
          <div className="min-w-[240px] flex-1 truncate px-2 text-text" title={p.name}>{p.name}</div>
          <div className="w-40 shrink-0 truncate px-2 text-text-secondary" title={`${p.product} ${p.version}`.trim()}>{p.product}{p.version ? ` ${p.version}` : ''}</div>
          <div className="w-48 shrink-0 truncate px-2 text-text-secondary" title={p.group}>{p.group || '—'}</div>
          <div className="w-20 shrink-0 px-2 text-text-secondary">{p.active ? 'да' : 'нет'}</div>
          <div className="w-16 shrink-0 px-2 text-right font-mono tabular-nums text-text-secondary">{p.groups}</div>
          <div className="w-16 shrink-0 px-2 text-right font-mono tabular-nums text-text-secondary">{p.hosts}</div>
          <div className="w-28 shrink-0 px-2"><GradeBadge grade={p.grade} reason={p.grade_reason} /></div>
          <div className="w-28 shrink-0 truncate px-2"><LocksCell p={p} /></div>
          <div className="w-24 shrink-0 px-2 text-right">
            {p.profiles === null ? <span className="text-text-secondary">не собрано</span> : <span className="font-mono tabular-nums text-text-secondary">{p.profiles}</span>}
          </div>
          <div className="w-24 shrink-0 px-2 text-right"><ExclusionsCell p={p} /></div>
          <div role="presentation" className="w-20 shrink-0 px-2 text-right" onClick={(e) => e.stopPropagation()} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') e.stopPropagation() }}>
            {p.findings > 0 ? (
              <Link to={`/ksc/servers/${serverId}/findings?q=${encodeURIComponent(p.name)}`} className="font-mono tabular-nums text-text hover:text-primary">{p.findings}</Link>
            ) : (
              <span className="font-mono tabular-nums text-text-secondary">0</span>
            )}
          </div>
          <ChevronRight size={14} className="mx-1 w-4 shrink-0 text-text-secondary/40" aria-hidden />
        </div>
      ))}
    </div>
  )
}

/** Вкладка «Политики»: плоский список политик снапшота с привязкой к группам и хостам; строка открывает карточку. */
export function PoliciesTable({ serverId, snapshotId }: { serverId: number; snapshotId: number }) {
  const [filters, setFilters] = useState<PolicyFilters>({})
  const [searchInput, setSearchInput] = useState('')
  const q = useDebouncedValue(searchInput, 250)
  const filtersPanel = useFiltersPanel('ksc-policy-list')
  const queryArgs = useMemo(() => ({ ...filters, q: q || undefined }), [filters, q])
  const query = usePolicyList(snapshotId, queryArgs)
  const items = query.data?.items ?? []
  const facets = query.data?.facets

  function toggle<K extends keyof PolicyFilters>(key: K, value: PolicyFilters[K]) { setFilters((prev) => ({ ...prev, [key]: value })) }
  function clearAll() { setFilters({}); setSearchInput('') }
  const chips: FilterChip[] = []
  if (filters.product) chips.push({ label: `продукт ${filters.product}`, clear: () => toggle('product', undefined) })
  if (filters.active !== undefined) chips.push({ label: filters.active ? 'активные' : 'неактивные', clear: () => toggle('active', undefined) })
  if (filters.grade) chips.push({ label: `оценка: ${gradeLabel(filters.grade)}`, clear: () => toggle('grade', undefined) })

  const hasFilters = chips.length > 0 || q !== ''
  const errorMessage = query.error instanceof ApiRequestError ? query.error.message : query.isError ? 'Не удалось загрузить политики' : null
  const products = Object.entries(facets?.product ?? {}).sort((a, b) => b[1] - a[1])

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex shrink-0 flex-wrap items-center gap-3 border-b border-grid bg-surface px-4 py-2.5">
        <FiltersButton open={filtersPanel.open} onToggle={filtersPanel.toggle} count={chips.length} />
        <div className="relative max-w-sm flex-1">
          <Search size={14} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-text-secondary" aria-hidden />
          <input value={searchInput} onChange={(e) => setSearchInput(e.target.value)} placeholder="Название политики" aria-label="Поиск по названию политики" className="w-full rounded border border-border bg-app-bg py-1.5 pr-3 pl-8 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" />
        </div>
        {hasFilters && <button type="button" onClick={clearAll} className="flex items-center gap-1.5 rounded px-2 py-1 text-xs text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"><FilterX size={13} aria-hidden /> Сбросить</button>}
        <div className="font-mono text-xs tabular-nums text-text-secondary">{query.data ? items.length : '…'}</div>
        {query.data && !query.data.profiles_collected && <span className="text-xs text-text-secondary">профили в этой выгрузке не собирались</span>}
        {!filtersPanel.open && <FilterChips chips={chips} />}
      </div>
      <div className="flex min-h-0 flex-1">
        {filtersPanel.open && (
          <FacetPanel total={items.length} noun="Политик">
            <FacetSection title="Оценка">
              {GRADE_FILTERS.map((g) => (
                <FacetRow key={g} active={filters.grade === g} count={facets?.grade?.[g] ?? 0} onClick={() => toggle('grade', filters.grade === g ? undefined : g)}>{gradeLabel(g)}</FacetRow>
              ))}
            </FacetSection>
            <FacetSection title="Активность">
              {([true, false] as const).map((a) => (
                <FacetRow key={String(a)} active={filters.active === a} count={facets?.active?.[String(a)]} onClick={() => toggle('active', filters.active === a ? undefined : a)}>{a ? 'активные' : 'неактивные'}</FacetRow>
              ))}
            </FacetSection>
            <FacetSection title="Продукт">
              {products.map(([p, n]) => (
                <FacetRow key={p} active={filters.product === p} count={n} onClick={() => toggle('product', filters.product === p ? undefined : p)}>{p}</FacetRow>
              ))}
            </FacetSection>
          </FacetPanel>
        )}
        <div className="min-w-0 flex-1 bg-app-bg">
          {query.isLoading && <FullPageSpinner />}
          {errorMessage && <div className="p-6"><ErrorState message={errorMessage} onRetry={() => query.refetch()} /></div>}
          {!query.isLoading && !errorMessage && items.length === 0 && (
            <div className="p-6">
              <EmptyState icon={FilterX} title={hasFilters ? 'Ничего не найдено' : 'Политик нет'} description={hasFilters ? 'Ни одна политика не подходит под фильтры.' : 'В снапшоте нет политик. Если выгрузка импортирована до появления этого списка, пересчитайте снапшот на экране «Снапшоты».'} />
            </div>
          )}
          {!query.isLoading && !errorMessage && items.length > 0 && <Table items={items} serverId={serverId} />}
        </div>
      </div>
    </div>
  )
}
