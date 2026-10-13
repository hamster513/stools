import { useEffect, useMemo, useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, FilterX, Search } from 'lucide-react'
import { useFindings, useRuleDetail } from '@/modules/siem/api/queries'
import { FINDING_KIND_LABELS, OBJECT_TYPE_LABELS, POLARITY_LABELS, SHAPE_LABELS, type FindingListItem } from '@/modules/siem/api/types'
import { ExportButton } from '@/platform/filters/ExportButton'
import { exportHref } from '@/platform/filters/exportHref'
import { facetValues, useRememberedFacets } from '@/platform/filters/useRememberedFacets'
import { FiltersButton, FilterChips, type FilterChip } from '@/platform/filters/FiltersBar'
import { useFiltersPanel } from '@/platform/filters/useFiltersPanel'
import { BulkBar } from '@/platform/findings/BulkBar'
import { findingFacetChips, valueChips } from '@/platform/findings/facets'
import { useUsersDirectory } from '@/platform/findings/queries'
import { useMe } from '@/api/auth'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { useCan } from '@/lib/can'
import { Link, useSearchParams } from '@/lib/router'
import { FacetPanel, type HygieneFilters } from './hygiene/FacetPanel'
import { FindingsTable } from './hygiene/FindingsTable'
import { DetailDrawer } from './hygiene/DetailDrawer'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { ErrorState } from '@/components/ui/ErrorState'
import { EmptyState } from '@/components/ui/EmptyState'
import { ApiRequestError } from '@/api/client'

function isTypingTarget(el: EventTarget | null): boolean {
  if (!(el instanceof HTMLElement)) return false
  return el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable
}

/**
 * Находки гигиены снапшота. Статусы — общие статусы находок платформы
 * (module `siem`, область 0): по умолчанию показаны открытые, галочки и
 * полоса массовой смены, в карточке — блок «Работа с находкой». `?key=` в
 * адресе (ссылка из «Моих находок») открывает карточку находки.
 */
export function HygienePage({ snapshotId }: { snapshotId: number }) {
  const searchParams = useSearchParams()
  const [filters, setFilters] = useState<HygieneFilters>(() => {
    const inTable = searchParams.get('in_table')
    return inTable === null ? {} : { in_table: inTable === 'true' }
  })
  const [searchInput, setSearchInput] = useState('')
  const q = useDebouncedValue(searchInput, 250)
  const [selectedIndex, setSelectedIndex] = useState(0)
  const [openFinding, setOpenFinding] = useState<FindingListItem | null>(null)
  const [checked, setChecked] = useState<ReadonlySet<string>>(new Set())
  const [anchor, setAnchor] = useState<number | null>(null)
  const searchRef = useRef<HTMLInputElement>(null)
  const filtersPanel = useFiltersPanel('siem-hygiene')
  const qc = useQueryClient()
  const me = useMe()
  const directory = useUsersDirectory()
  const names = useMemo(() => new Map((directory.data ?? []).map((u) => [u.login, u.display_name || u.login])), [directory.data])
  // Изменения статусов — решения, а решения аудитор не выносит: галочек и полосы у него нет.
  const { write } = useCan()

  // Экран открывают двумя путями: из инвентаря по конкретному правилу
  // и целиком по снапшоту. Правило приходит идентификатором в адресе —
  // это делает ссылку из инвентаря воспроизводимой и разделяемой.
  const objectUuid = searchParams.get('object_uuid') ?? undefined
  const rule = useRuleDetail(objectUuid, snapshotId)

  const queryArgs = useMemo(() => {
    const { status, assignee, overdue, risk_expiring, ...own } = filters
    return {
      snapshot_id: snapshotId,
      object_uuid: objectUuid,
      ...own,
      status,
      assignee,
      overdue,
      risk_expiring,
      q: q || undefined,
    }
  }, [snapshotId, objectUuid, filters, q])
  const query = useFindings(queryArgs)

  // Карточка по ссылке `?key=`: находка ищется в любом статусе, один раз.
  const linkedKey = searchParams.get('key')
  const linked = useFindings({ snapshot_id: snapshotId, key: linkedKey ?? undefined, status: 'all' }, { enabled: linkedKey !== null })
  const linkedItem = linked.data?.pages[0]?.items[0]
  const linkedShown = useRef(false)
  useEffect(() => {
    if (linkedItem && !linkedShown.current) {
      linkedShown.current = true
      setOpenFinding(linkedItem)
    }
  }, [linkedItem])

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
  const first = query.data?.pages[0]
  // Соли ключей нет: статусы не сопоставить, и менять их нельзя — решение легло бы на чужой ключ.
  const keysBroken = first?.status_keys_broken === true
  // Память фасетов — на странице, а не в панели: панель по умолчанию закрыта и при закрытии забывала бы значения.
  const remembered = useRememberedFacets(facets ? {
    field: facetValues(facets.field).slice(0, 12),
    assignee: facetValues(facets.assignee),
  } : undefined)

  useEffect(() => {
    setSelectedIndex(0)
    setChecked(new Set())
    setAnchor(null)
  }, [queryArgs])

  const selected: FindingListItem | null = items[selectedIndex] ?? null
  // Открытая карточка — со свежими полями, если находка есть в обновлённом списке.
  const shownFinding = openFinding ? (items.find((f) => f.id === openFinding.id) ?? openFinding) : null

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

  function refresh() {
    qc.invalidateQueries({ queryKey: ['findings'] })
    // «Требует внимания» в инвентаре и карточке правила зависит от статусов.
    qc.invalidateQueries({ queryKey: ['rules'] })
    qc.invalidateQueries({ queryKey: ['rule-detail'] })
  }

  function toggleFilter<K extends keyof HygieneFilters>(key: K, value: HygieneFilters[K]) {
    setFilters((prev) => ({ ...prev, [key]: value }))
  }

  function clearFilters() {
    setFilters({})
    setSearchInput('')
  }

  // Что выбрано, пока панель свёрнута: фильтр из ссылки не должен действовать незаметно.
  // Чип на каждое выбранное значение: крестик снимает только его.
  const chips: FilterChip[] = findingFacetChips(filters, (next) => setFilters((prev) => ({ ...prev, ...next })), names)
  chips.push(...valueChips('Класс', filters.kind, (k) => FINDING_KIND_LABELS[k], (v) => toggleFilter('kind', v)))
  chips.push(...valueChips('Тип', filters.object_type, (t) => OBJECT_TYPE_LABELS[t], (v) => toggleFilter('object_type', v)))
  chips.push(...valueChips('Полярность', filters.polarity, (p) => POLARITY_LABELS[p], (v) => toggleFilter('polarity', v)))
  chips.push(...valueChips('Форма', filters.shape, (f) => SHAPE_LABELS[f], (v) => toggleFilter('shape', v)))
  if (filters.in_table !== undefined) chips.push({ label: filters.in_table ? 'есть в табличном списке' : 'нет в табличном списке', clear: () => toggleFilter('in_table', undefined) })
  chips.push(...valueChips('Поле', filters.field, (f) => f, (v) => toggleFilter('field', v)))

  // --- Клавиатура: j/k строки, Enter раскрыть, / поиск, Esc свернуть.
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        if (openFinding !== null) {
          setOpenFinding(null)
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
        if (selected) setOpenFinding(selected)
      }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [items.length, selected, openFinding])

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
        <ExportButton href={exportHref('/api/siem/findings/export', queryArgs)} total={first?.total} disabled={query.isLoading} />
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
      {first && !first.is_latest && <div className="shrink-0 border-b border-grid bg-surface px-4 py-1.5 text-[11px] text-text-secondary">Статусы показаны на сегодня, находки — на дату снапшота</div>}
      {keysBroken && <div role="alert" className="shrink-0 border-b border-grid bg-surface px-4 py-1.5 text-[11px] text-text">Статусы находок недоступны: потерян ключ сопоставления (app_setting.siem_finding_key). Восстановите его из резервной копии — до тех пор все находки показаны как «Новая».</div>}
      {write && !keysBroken && (
        <BulkBar
          module="siem"
          scopeId={0}
          keys={[...checked]}
          total={total}
          onDone={() => { setChecked(new Set()); setAnchor(null); refresh() }}
          onClear={() => setChecked(new Set())}
        />
      )}

      <div className="flex min-h-0 flex-1">
        {filtersPanel.open && <FacetPanel facets={facets} remembered={remembered} filters={filters} onToggle={toggleFilter} total={total} myLogin={me.data?.login} names={names} />}

        <div className="min-w-0 flex-1 bg-app-bg">
          {query.isLoading && <FullPageSpinner />}
          {errorMessage && <div className="p-6"><ErrorState message={errorMessage} onRetry={() => query.refetch()} /></div>}
          {!query.isLoading && !errorMessage && items.length === 0 && (
            <div className="p-6">
              <EmptyState
                icon={FilterX}
                title={hasActiveFilters ? 'Ничего не найдено' : 'Открытых находок нет'}
                description={hasActiveFilters
                  ? 'Ни одна находка не подходит под текущие фильтры. Сбросьте фильтры или измените запрос поиска.'
                  : 'В этом снапшоте нет открытых находок; остальные — в фильтре по статусу.'}
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
              onOpen={(index) => setOpenFinding(items[index])}
              onReachEnd={() => {
                if (query.hasNextPage && !query.isFetchingNextPage) query.fetchNextPage()
              }}
              {...(write && !keysBroken ? { checked, onCheck: check, onCheckAll: (on: boolean) => setChecked(on ? new Set(items.map((f) => f.key)) : new Set()) } : {})}
            />
          )}
        </div>
      </div>

      <DetailDrawer
        finding={shownFinding}
        ordinal={shownFinding ? items.findIndex((f) => f.id === shownFinding.id) + 1 || null : null}
        onClose={() => setOpenFinding(null)}
        onChanged={refresh}
        statusesAvailable={!keysBroken}
      />
    </div>
  )
}
