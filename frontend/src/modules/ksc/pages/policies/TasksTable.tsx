import { useMemo, useState } from 'react'
import { FilterX, Search } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useTasks } from '@/modules/ksc/api/queries'
import type { TaskListItem, TasksQuery } from '@/modules/ksc/api/types'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { FiltersButton, FilterChips, type FilterChip } from '@/platform/filters/FiltersBar'
import { useFiltersPanel } from '@/platform/filters/useFiltersPanel'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { cn } from '@/lib/cn'
import { FacetPanel, FacetRow, FacetSection } from './Facets'

type TaskFilters = Pick<TasksQuery, 'type' | 'failed'>

function when(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'никогда'
}

function Table({ items }: { items: TaskListItem[] }) {
  return (
    <div className="h-full overflow-auto">
      <div className="sticky top-0 z-10 flex min-w-[1180px] border-b border-grid bg-surface text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
        <div className="w-48 shrink-0 px-2 py-2">Тип</div>
        <div className="min-w-[220px] flex-1 px-2 py-2">Название</div>
        <div className="w-40 shrink-0 px-2 py-2">Продукт</div>
        <div className="w-48 shrink-0 px-2 py-2">Группа</div>
        <div className="w-24 shrink-0 px-2 py-2 text-right">Расписание</div>
        <div className="w-36 shrink-0 px-2 py-2">Последний запуск</div>
        <div className="w-16 shrink-0 px-2 py-2 text-right">Успех</div>
        <div className="w-20 shrink-0 px-2 py-2 text-right">Предупр.</div>
        <div className="w-16 shrink-0 px-2 py-2 text-right">Провал</div>
      </div>
      {items.map((t) => (
        <div key={t.id} className="flex min-w-[1180px] items-center border-b border-grid py-2 text-xs">
          <div className="w-48 shrink-0 truncate px-2 text-text" title={t.type}>{t.type}</div>
          <div className="min-w-[220px] flex-1 truncate px-2 text-text" title={t.name}>{t.name}</div>
          <div className="w-40 shrink-0 truncate px-2 text-text-secondary" title={t.product}>{t.product || '—'}</div>
          <div className="w-48 shrink-0 truncate px-2 text-text-secondary" title={t.group}>{t.group || 'набор устройств'}</div>
          {/* Код типа расписания KSC как пришёл: словаря кодов в модуле пока нет. */}
          <div className="w-24 shrink-0 px-2 text-right font-mono tabular-nums text-text-secondary" title="код типа расписания">{t.schedule}</div>
          <div className="w-36 shrink-0 truncate px-2 text-text-secondary">{when(t.last_run_at)}</div>
          <div className="w-16 shrink-0 px-2 text-right font-mono tabular-nums text-text-secondary">{t.ok}</div>
          <div className={cn('w-20 shrink-0 px-2 text-right font-mono tabular-nums', t.warning > 0 ? 'text-risk-medium' : 'text-text-secondary')}>{t.warning}</div>
          <div className={cn('w-16 shrink-0 px-2 text-right font-mono tabular-nums', t.failed > 0 ? 'font-medium text-risk-high' : 'text-text-secondary')}>{t.failed}</div>
        </div>
      ))}
    </div>
  )
}

/** Вкладка «Задачи»: плоский список всех задач выгрузки — групповых и для наборов устройств. */
export function TasksTable({ snapshotId }: { snapshotId: number }) {
  const [filters, setFilters] = useState<TaskFilters>({})
  const [searchInput, setSearchInput] = useState('')
  const q = useDebouncedValue(searchInput, 250)
  const filtersPanel = useFiltersPanel('ksc-tasks')
  const queryArgs = useMemo(() => ({ ...filters, q: q || undefined }), [filters, q])
  const query = useTasks(snapshotId, queryArgs)
  const items = query.data?.items ?? []

  function toggle<K extends keyof TaskFilters>(key: K, value: TaskFilters[K]) { setFilters((prev) => ({ ...prev, [key]: value })) }
  function clearAll() { setFilters({}); setSearchInput('') }
  const chips: FilterChip[] = []
  if (filters.type) chips.push({ label: `тип ${filters.type}`, clear: () => toggle('type', undefined) })
  if (filters.failed) chips.push({ label: 'есть провалы', clear: () => toggle('failed', undefined) })

  const hasFilters = chips.length > 0 || q !== ''
  const errorMessage = query.error instanceof ApiRequestError ? query.error.message : query.isError ? 'Не удалось загрузить задачи' : null
  const types = Object.entries(query.data?.facets.type ?? {}).sort((a, b) => b[1] - a[1])

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex shrink-0 flex-wrap items-center gap-3 border-b border-grid bg-surface px-4 py-2.5">
        <FiltersButton open={filtersPanel.open} onToggle={filtersPanel.toggle} count={chips.length} />
        <div className="relative max-w-sm flex-1">
          <Search size={14} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-text-secondary" aria-hidden />
          <input value={searchInput} onChange={(e) => setSearchInput(e.target.value)} placeholder="Название задачи" aria-label="Поиск по названию задачи" className="w-full rounded border border-border bg-app-bg py-1.5 pr-3 pl-8 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" />
        </div>
        {hasFilters && <button type="button" onClick={clearAll} className="flex items-center gap-1.5 rounded px-2 py-1 text-xs text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"><FilterX size={13} aria-hidden /> Сбросить</button>}
        <div className="font-mono text-xs tabular-nums text-text-secondary">{query.data ? items.length : '…'}</div>
        {!filtersPanel.open && <FilterChips chips={chips} />}
      </div>
      <div className="flex min-h-0 flex-1">
        {filtersPanel.open && (
          <FacetPanel total={items.length} noun="Задач">
            <FacetSection title="Запуски">
              <FacetRow active={filters.failed === true} onClick={() => toggle('failed', filters.failed ? undefined : true)}>есть провалы</FacetRow>
            </FacetSection>
            <FacetSection title="Тип">
              {types.map(([t, n]) => (
                <FacetRow key={t} active={filters.type === t} count={n} onClick={() => toggle('type', filters.type === t ? undefined : t)}>{t}</FacetRow>
              ))}
            </FacetSection>
          </FacetPanel>
        )}
        <div className="min-w-0 flex-1 bg-app-bg">
          {query.isLoading && <FullPageSpinner />}
          {errorMessage && <div className="p-6"><ErrorState message={errorMessage} onRetry={() => query.refetch()} /></div>}
          {!query.isLoading && !errorMessage && items.length === 0 && (
            <div className="p-6">
              <EmptyState icon={FilterX} title={hasFilters ? 'Ничего не найдено' : 'Задач нет'} description={hasFilters ? 'Ни одна задача не подходит под фильтры.' : 'В выгрузке нет задач.'} />
            </div>
          )}
          {!query.isLoading && !errorMessage && items.length > 0 && <Table items={items} />}
        </div>
      </div>
    </div>
  )
}
