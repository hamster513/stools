import { useEffect, useMemo, useRef, useState } from 'react'
import { ArrowLeft, FilterX, Search } from 'lucide-react'
import { useFindings, useRuleDetail, useSetVerdict } from '@/modules/siem/api/queries'
import { FINDING_KIND_LABELS, FINDING_STATUS_LABELS, OBJECT_TYPE_LABELS, POLARITY_LABELS, SHAPE_LABELS, type FindingListItem } from '@/modules/siem/api/types'
import { FiltersButton, FilterChips, type FilterChip } from '@/platform/filters/FiltersBar'
import { useFiltersPanel } from '@/platform/filters/useFiltersPanel'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { useCan } from '@/lib/can'
import { Link, useSearchParams } from '@/lib/router'
import { FacetPanel, type HygieneFilters } from './hygiene/FacetPanel'
import { FindingsTable } from './hygiene/FindingsTable'
import { DetailDrawer } from './hygiene/DetailDrawer'
import { AcceptDialog } from './hygiene/AcceptDialog'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { ErrorState } from '@/components/ui/ErrorState'
import { EmptyState } from '@/components/ui/EmptyState'
import { ApiRequestError } from '@/api/client'

function isTypingTarget(el: EventTarget | null): boolean {
  if (!(el instanceof HTMLElement)) return false
  return el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable
}

export function HygienePage({ snapshotId }: { snapshotId: number }) {
  const searchParams = useSearchParams()
  const [filters, setFilters] = useState<HygieneFilters>(() => {
    const inTable = searchParams.get('in_table')
    return inTable === null ? {} : { in_table: inTable === 'true' }
  })
  const [searchInput, setSearchInput] = useState('')
  const q = useDebouncedValue(searchInput, 250)
  const [selectedIndex, setSelectedIndex] = useState(0)
  const [openFindingId, setOpenFindingId] = useState<number | null>(null)
  const [acceptFindingId, setAcceptFindingId] = useState<number | null>(null)
  const searchRef = useRef<HTMLInputElement>(null)
  const filtersPanel = useFiltersPanel('siem-hygiene')

  // Экран открывают двумя путями: из инвентаря по конкретному правилу
  // и целиком по снапшоту. Правило приходит идентификатором в адресе —
  // это делает ссылку из инвентаря воспроизводимой и разделяемой.
  const objectUuid = searchParams.get('object_uuid') ?? undefined
  const rule = useRuleDetail(objectUuid, snapshotId)

  const query = useFindings({
    snapshot_id: snapshotId,
    object_uuid: objectUuid,
    ...filters,
    q: q || undefined,
  })

  // Страницы склеиваются в один список: таблица виртуализирована, и для
  // неё это по-прежнему один массив, просто растущий по мере прокрутки.
  const items = useMemo(
    () => query.data?.pages.flatMap((page) => page.items) ?? [],
    [query.data],
  )

  // Фасеты и общее число берутся с сервера: они посчитаны по всему
  // снапшоту, а не по загруженной части. Иначе счётчики менялись бы
  // при прокрутке, и это читалось бы как поломка.
  const facets = query.data?.pages[0]?.facets
  const total = query.data?.pages[0]?.total ?? 0
  const fieldFacet = facets?.field

  useEffect(() => {
    setSelectedIndex(0)
  }, [filters, q])

  const selected: FindingListItem | null = items[selectedIndex] ?? null
  const openFinding = items.find((f) => f.id === openFindingId) ?? null
  const acceptFinding = items.find((f) => f.id === acceptFindingId) ?? null

  const verdict = useSetVerdict()
  // Горячая клавиша «a» — тот же вердикт, что и кнопка в ящике: скрыв
  // кнопку и оставив клавишу, мы вернули бы аудитору 403 обходным путём.
  const { write } = useCan()

  function toggleFilter<K extends keyof HygieneFilters>(key: K, value: HygieneFilters[K]) {
    setFilters((prev) => ({ ...prev, [key]: value }))
  }

  function clearFilters() {
    setFilters({})
    setSearchInput('')
  }

  // Что выбрано, пока панель свёрнута: фильтр из ссылки не должен действовать незаметно.
  const chips: FilterChip[] = []
  if (filters.kind) chips.push({ label: `класс ${FINDING_KIND_LABELS[filters.kind]}`, clear: () => toggleFilter('kind', undefined) })
  if (filters.object_type) chips.push({ label: `тип ${OBJECT_TYPE_LABELS[filters.object_type]}`, clear: () => toggleFilter('object_type', undefined) })
  if (filters.polarity) chips.push({ label: `полярность ${POLARITY_LABELS[filters.polarity]}`, clear: () => toggleFilter('polarity', undefined) })
  if (filters.shape) chips.push({ label: `форма ${SHAPE_LABELS[filters.shape]}`, clear: () => toggleFilter('shape', undefined) })
  if (filters.in_table !== undefined) chips.push({ label: filters.in_table ? 'есть в табличном списке' : 'нет в табличном списке', clear: () => toggleFilter('in_table', undefined) })
  if (filters.status) chips.push({ label: `статус ${FINDING_STATUS_LABELS[filters.status]}`, clear: () => toggleFilter('status', undefined) })
  if (filters.field) chips.push({ label: `поле ${filters.field}`, clear: () => toggleFilter('field', undefined) })

  // --- Клавиатура: j/k строки, Enter раскрыть, a принять, / поиск, Esc свернуть.
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        if (openFindingId !== null) {
          setOpenFindingId(null)
          return
        }
        if (acceptFindingId !== null) {
          setAcceptFindingId(null)
          return
        }
        if (document.activeElement instanceof HTMLElement) document.activeElement.blur()
        return
      }

      if (isTypingTarget(e.target)) return

      if (e.key === '/') {
        e.preventDefault()
        searchRef.current?.focus()
        return
      }
      if (e.key === 'j') {
        e.preventDefault()
        setSelectedIndex((i) => Math.min(items.length - 1, i + 1))
        return
      }
      if (e.key === 'k') {
        e.preventDefault()
        setSelectedIndex((i) => Math.max(0, i - 1))
        return
      }
      if (e.key === 'Enter') {
        e.preventDefault()
        if (selected) setOpenFindingId(selected.id)
        return
      }
      if (e.key === 'a' && write) {
        e.preventDefault()
        if (selected) setAcceptFindingId(selected.id)
      }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [items.length, selected, openFindingId, acceptFindingId, write])

  const hasActiveFilters = Object.values(filters).some((v) => v !== undefined) || q !== ''

  const errorMessage =
    query.error instanceof ApiRequestError ? query.error.message : query.isError ? 'Не удалось загрузить находки' : null

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex shrink-0 flex-wrap items-center gap-3 border-b border-grid bg-surface px-4 py-2.5">
        {objectUuid ? (
          <div className="flex min-w-0 items-center gap-2">
            <Link
              to={`/siem/snapshots/${snapshotId}/rules`}
              className="flex items-center gap-1 rounded px-1.5 py-1 text-xs text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
            >
              <ArrowLeft size={13} aria-hidden />
              Инвентарь
            </Link>
            <h1 className="truncate font-mono text-sm text-text" title={rule.data?.name}>
              {rule.data?.name ?? '…'}
            </h1>
          </div>
        ) : (
          <h1 className="text-sm font-semibold text-text">Находки</h1>
        )}
        <FiltersButton open={filtersPanel.open} onToggle={filtersPanel.toggle} count={chips.length} />
        <div className="relative flex-1 max-w-sm">
          <Search size={14} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-text-secondary" aria-hidden />
          <input
            ref={searchRef}
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder="Поиск по объекту, полю, списку… (/)"
            className="w-full rounded border border-border bg-app-bg py-1.5 pr-3 pl-8 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
          />
        </div>
        {hasActiveFilters && (
          <button
            type="button"
            onClick={clearFilters}
            className="flex items-center gap-1.5 rounded px-2 py-1 text-xs text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
          >
            <FilterX size={13} aria-hidden />
            Сбросить фильтры
          </button>
        )}
        <div className="font-mono text-xs tabular-nums text-text-secondary">
          {query.data
            ? items.length < total
              ? `${items.length} из ${total} находок`
              : `${total} находок`
            : '…'}
        </div>
        {!filtersPanel.open && <FilterChips chips={chips} />}
      </header>

      <div className="flex min-h-0 flex-1">
        {filtersPanel.open && <FacetPanel facets={facets} fieldFacet={fieldFacet} filters={filters} onToggle={toggleFilter} total={total} />}

        <div className="min-w-0 flex-1 bg-app-bg">
          {query.isLoading && <FullPageSpinner />}
          {errorMessage && <div className="p-6"><ErrorState message={errorMessage} onRetry={() => query.refetch()} /></div>}
          {!query.isLoading && !errorMessage && items.length === 0 && (
            <div className="p-6">
              <EmptyState
                icon={FilterX}
                title="Ничего не найдено"
                description="Ни одна находка не подходит под текущие фильтры. Сбросьте фильтры или измените запрос поиска."
                action={
                  hasActiveFilters ? (
                    <button
                      type="button"
                      onClick={clearFilters}
                      className="rounded bg-primary px-3 py-1.5 text-xs font-medium text-primary-text hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
                    >
                      Сбросить фильтры
                    </button>
                  ) : undefined
                }
              />
            </div>
          )}
          {!query.isLoading && !errorMessage && items.length > 0 && (
            <FindingsTable
              items={items}
              offset={0}
              selectedIndex={selectedIndex}
              onSelectIndex={setSelectedIndex}
              onOpen={(index) => setOpenFindingId(items[index].id)}
              onReachEnd={() => {
                if (query.hasNextPage && !query.isFetchingNextPage) query.fetchNextPage()
              }}
            />
          )}
        </div>
      </div>

      <DetailDrawer
        finding={openFinding}
        ordinal={openFinding ? items.findIndex((f) => f.id === openFinding.id) + 1 : null}
        onClose={() => setOpenFindingId(null)}
        onAccept={() => {
          if (openFinding) setAcceptFindingId(openFinding.id)
        }}
        onTakeInWork={() => {
          if (openFinding) verdict.mutate({ finding_id: openFinding.id, status: 'in_progress' })
        }}
      />

      <AcceptDialog
        finding={acceptFinding}
        pending={verdict.isPending}
        onConfirm={(reason) => {
          if (!acceptFinding) return
          verdict.mutate(
            { finding_id: acceptFinding.id, status: 'accepted', reason },
            { onSuccess: () => setAcceptFindingId(null) },
          )
        }}
        onCancel={() => setAcceptFindingId(null)}
      />
    </div>
  )
}
