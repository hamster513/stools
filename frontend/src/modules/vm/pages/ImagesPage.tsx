import { useEffect, useMemo, useRef, useState } from 'react'
import { Container, FilterX, RefreshCw, Search } from 'lucide-react'
import { buildQuery, errorText } from '@/api/client'
import { useHarbor, useImages } from '@/modules/vm/api/queries'
import {
  ARTIFACT_KINDS, ARTIFACT_LABELS, IMAGE_LEVEL_LABELS, IMAGE_LEVELS, SCAN_STATUS_LABELS, SCAN_STATUSES,
  type ImageItem, type ImageLevel, type ImageScanStatus, type ImageSort,
} from '@/modules/vm/api/types'
import { ExportButton } from '@/platform/filters/ExportButton'
import { exportHref } from '@/platform/filters/exportHref'
import { facetValues, useRememberedFacets } from '@/platform/filters/useRememberedFacets'
import { FiltersButton, FilterChips, type FilterChip } from '@/platform/filters/FiltersBar'
import { useFiltersPanel } from '@/platform/filters/useFiltersPanel'
import { listFrom, valueChips } from '@/platform/findings/facets'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { useCan } from '@/lib/can'
import { Link, useRouter, useSearchParams } from '@/lib/router'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { ImagesFacetPanel, type ImageFilters } from './images/ImagesFacetPanel'
import { ImagesTable } from './images/ImagesTable'
import { HarborSyncStatus } from './images/HarborSyncStatus'
import { useHarborSync } from './images/useHarborSync'

function isTypingTarget(el: EventTarget | null): boolean {
  return el instanceof HTMLElement && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable)
}

const SORTS: ImageSort[] = ['risk_desc', 'name', 'pushed_desc', 'trivy_desc']
const DEFAULT_SORT: ImageSort = 'risk_desc'
const TRIVY_FLAGS = ['critical', 'high'] as const
const TRIVY_CHIP_LABELS = { critical: 'есть критические', high: 'есть высокие' } as const

/**
 * Образы контейнеров из Harbor: список с фасетами, наибольшим риском находок,
 * оценкой Trivy и выгрузкой. Фильтры, поиск и сортировка — в адресе: со страницы
 * образа «назад» возвращает тот же отбор. Строка открывает страницу образа.
 */
export function ImagesPage() {
  const params = useSearchParams()
  const { search, navigate } = useRouter()
  const [filters, setFilters] = useState<ImageFilters>(() => ({
    artifact_kind: listFrom(params, 'artifact_kind', ARTIFACT_KINDS),
    project: listFrom(params, 'project'),
    scan_status: listFrom<ImageScanStatus>(params, 'scan_status', SCAN_STATUSES),
    level: listFrom<ImageLevel>(params, 'level', IMAGE_LEVELS),
    trivy: listFrom(params, 'trivy', TRIVY_FLAGS),
    running_only: ['true', '1'].includes(params.get('running_only') ?? '') || undefined,
  }))
  const [sort, setSort] = useState<ImageSort>(() => {
    const s = params.get('sort') as ImageSort | null
    return s && SORTS.includes(s) ? s : DEFAULT_SORT
  })
  const [searchInput, setSearchInput] = useState(() => params.get('q') ?? '')
  const q = useDebouncedValue(searchInput, 250)
  const [selectedIndex, setSelectedIndex] = useState(0)
  const searchRef = useRef<HTMLInputElement>(null)
  const filtersPanel = useFiltersPanel('vm-images')
  const { write } = useCan()
  const harbor = useHarbor()
  const harborSync = useHarborSync()

  const queryArgs = useMemo(() => ({ ...filters, q: q || undefined, sort }), [filters, q, sort])
  const query = useImages(queryArgs)
  const items = useMemo(() => query.data?.pages.flatMap((p) => p.items) ?? [], [query.data])
  const facets = query.data?.pages[0]?.facets ?? undefined
  const total = query.data?.pages[0]?.total ?? 0
  // Память фасетов — на странице: панель по умолчанию закрыта и при закрытии забывала бы значения.
  const remembered = useRememberedFacets(facets ? {
    project: facetValues(facets.project), scan_status: facetValues(facets.scan_status),
  } : undefined)

  // Отбор — в адрес без новой записи истории; сортировка по умолчанию не пишется.
  useEffect(() => {
    const next = buildQuery({ ...queryArgs, sort: sort === DEFAULT_SORT ? undefined : sort })
    if (next !== search) navigate(`/vm/images${next}`, { replace: true })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [queryArgs])
  useEffect(() => { setSelectedIndex(0) }, [queryArgs])

  const selected: ImageItem | null = items[selectedIndex] ?? null

  function toggle<K extends keyof ImageFilters>(key: K, value: ImageFilters[K]) {
    setFilters((prev) => ({ ...prev, [key]: value }))
  }
  function clearAll() {
    setFilters({})
    setSearchInput('')
  }

  // Что выбрано, пока панель свёрнута: фильтр из ссылки не должен действовать незаметно.
  const chips: FilterChip[] = [
    ...(filters.running_only ? [{ label: 'Только запущенные на хостах', clear: () => toggle('running_only', undefined) }] : []),
    ...valueChips('Тип', filters.artifact_kind, (kind) => ARTIFACT_LABELS[kind], (v) => toggle('artifact_kind', v)),
    ...valueChips('Проект', filters.project, (p) => p, (v) => toggle('project', v)),
    ...valueChips('Скан', filters.scan_status, (s) => SCAN_STATUS_LABELS[s], (v) => toggle('scan_status', v)),
    ...valueChips('Риск', filters.level, (l) => IMAGE_LEVEL_LABELS[l], (v) => toggle('level', v)),
    ...valueChips('Trivy', filters.trivy, (t) => TRIVY_CHIP_LABELS[t], (v) => toggle('trivy', v)),
  ]

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        if (document.activeElement instanceof HTMLElement) document.activeElement.blur()
        return
      }
      if (isTypingTarget(e.target)) return
      // Enter на кнопке или ссылке нажимает её, а не открывает выбранный образ.
      if (e.key === 'Enter' && e.target instanceof HTMLElement && (e.target.tagName === 'BUTTON' || e.target.tagName === 'A')) return
      if (e.key === '/') { e.preventDefault(); searchRef.current?.focus(); return }
      if (e.key === 'j') { e.preventDefault(); setSelectedIndex((i) => Math.min(items.length - 1, i + 1)); return }
      if (e.key === 'k') { e.preventDefault(); setSelectedIndex((i) => Math.max(0, i - 1)); return }
      if (e.key === 'Enter' && selected) { e.preventDefault(); navigate(`/vm/images/${selected.id}`) }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [items.length, selected, navigate])

  const hasFilters = Object.values(filters).some((v) => v !== undefined) || q !== ''
  const configured = harbor.data?.configured ?? false
  // Пустой список ждёт и подключения: от него зависит, какое пустое состояние показать.
  const loading = query.isLoading || (items.length === 0 && harbor.isLoading)
  // Без списка и без настроек подключения пустое состояние было бы ложным: показываем ошибку.
  const harborFailed = items.length === 0 && !query.isError && harbor.isError
  const errorMessage = query.isError
    ? errorText(query.error, 'Не удалось загрузить образы')
    : harborFailed ? errorText(harbor.error, 'Не удалось загрузить настройки Harbor') : null
  const retry = () => { if (query.isError) query.refetch(); else harbor.refetch() }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex shrink-0 flex-wrap items-center gap-3 border-b border-grid bg-surface px-4 py-2.5">
        <h1 className="text-sm font-semibold text-text">Образы контейнеров</h1>
        <FiltersButton open={filtersPanel.open} onToggle={filtersPanel.toggle} count={chips.length} />
        <ExportButton href={exportHref('/api/vm/images/export', queryArgs)} total={query.data?.pages[0]?.total} disabled={query.isLoading} />
        <div className="relative max-w-sm flex-1">
          <Search size={14} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-text-secondary" aria-hidden />
          <input
            ref={searchRef}
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder="Образ или тег… (/)"
            aria-label="Поиск по образу и тегу"
            className="w-full rounded border border-border bg-app-bg py-1.5 pr-3 pl-8 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
          />
        </div>
        {hasFilters && (
          <button type="button" onClick={clearAll} className="flex items-center gap-1.5 rounded px-2 py-1 text-xs text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">
            <FilterX size={13} aria-hidden /> Сбросить
          </button>
        )}
        <div className="font-mono text-xs tabular-nums text-text-secondary">
          {query.data ? (items.length < total ? `${items.length.toLocaleString('ru-RU')} из ${total.toLocaleString('ru-RU')}` : total.toLocaleString('ru-RU')) : '…'}
        </div>
        {write && configured && (
          <Button className="ml-auto px-2 py-1 text-xs" onClick={harborSync.start} loading={harborSync.sync.isPending} disabled={harborSync.busy}>
            {!harborSync.sync.isPending && <RefreshCw size={13} className={harborSync.busy ? 'animate-spin' : undefined} aria-hidden />}
            Синхронизировать
          </Button>
        )}
        {!filtersPanel.open && <FilterChips chips={chips} />}
      </header>

      <HarborSyncStatus state={harborSync} className="shrink-0 border-b border-grid bg-surface px-4 py-1.5" />

      <div className="flex min-h-0 flex-1">
        {filtersPanel.open && <ImagesFacetPanel facets={facets} remembered={remembered} filters={filters} onToggle={toggle} total={total} />}
        <div className="min-w-0 flex-1 bg-app-bg">
          {loading && <FullPageSpinner />}
          {errorMessage && <div className="p-6"><ErrorState message={errorMessage} onRetry={retry} /></div>}
          {!loading && !errorMessage && items.length === 0 && (
            <div className="p-6">
              {hasFilters ? (
                <EmptyState icon={FilterX} title="Ничего не найдено" description="Ни один образ не подходит под фильтры. Сбросьте их или измените запрос." />
              ) : harbor.data && !configured ? (
                <EmptyState
                  icon={Container}
                  title="Подключение к Harbor не настроено"
                  description={write
                    ? 'Образы и отчёты Trivy приходят из реестра Harbor. Укажите адрес Harbor и учётную запись робота в настройках модуля VM.'
                    : 'Образы и отчёты Trivy приходят из реестра Harbor. Подключение настраивает администратор модуля VM.'}
                  action={write && (
                    <Link to="/settings/vm#harbor" className="text-sm text-primary underline underline-offset-2 hover:text-text">Настроить</Link>
                  )}
                />
              ) : (
                <EmptyState
                  icon={Container}
                  title="Образов пока нет: запустите синхронизацию"
                  description={write
                    ? 'Подключение к Harbor настроено, но образы ещё не получены. Нажмите «Синхронизировать» — образы и отчёты Trivy придут из выбранных проектов.'
                    : 'Подключение к Harbor настроено, но образы ещё не получены. Синхронизацию запускает пользователь с правом записи в модуле VM.'}
                />
              )}
            </div>
          )}
          {!query.isLoading && !errorMessage && items.length > 0 && (
            <ImagesTable
              items={items}
              selectedIndex={selectedIndex}
              sort={sort}
              onSort={setSort}
              onSelectIndex={setSelectedIndex}
              onOpen={(i) => navigate(`/vm/images/${items[i].id}`)}
              onReachEnd={() => {
                if (query.hasNextPage && !query.isFetchingNextPage) query.fetchNextPage()
              }}
            />
          )}
        </div>
      </div>
    </div>
  )
}
