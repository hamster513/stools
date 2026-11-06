import { useEffect, useMemo, useRef, useState } from 'react'
import { useInfiniteQuery } from '@tanstack/react-query'
import { FilterX, Search } from 'lucide-react'
import { api, ApiRequestError, buildQuery } from '@/api/client'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { useRouter, useSearchParams } from '@/lib/router'
import { ExportButton } from '@/platform/filters/ExportButton'
import { exportHref } from '@/platform/filters/exportHref'
import { FiltersButton, FilterChips, type FilterChip } from '@/platform/filters/FiltersBar'
import { useFiltersPanel } from '@/platform/filters/useFiltersPanel'
import { FacetRow, FacetSection } from './AssetsPage'
import { ImageDrawer, type ImageRef } from './container-images/ImageDrawer'
import { ImagesTable } from './container-images/ImagesTable'
import { SOURCES, STATES, when, type Catalog, type Source, type State } from './container-images/types'

const SOURCE_KEYS = Object.keys(SOURCES) as Source[]
const STATE_KEYS = Object.keys(STATES) as State[]
const PAGE_SIZE = 100

export function ContainerImagesPage() {
  const params = useSearchParams()
  const { navigate } = useRouter()
  const searchRef = useRef<HTMLInputElement>(null)
  const filtersPanel = useFiltersPanel('assets-container-images')
  const sources = [...new Set(params.getAll('source').filter((v): v is Source => SOURCE_KEYS.includes(v as Source)))]
  const states = [...new Set(params.getAll('status').filter((v): v is State => STATE_KEYS.includes(v as State)))]
  const requestedId = Number(params.get('image'))
  const focusedId = sources.length === 1 && Number.isInteger(requestedId) && requestedId > 0 ? requestedId : null
  const focusedKey = focusedId ? `${sources[0]}:${focusedId}` : null
  const search = params.get('q') || ''
  const debounced = useDebouncedValue(search, 250)
  const q = focusedId ? '' : debounced
  const queryArgs = { q, source: sources, status: states, image_id: focusedId ?? undefined }
  const [selectedIndex, setSelectedIndex] = useState(0)
  const [selection, setSelection] = useState<{ focus: string | null; image: ImageRef | null }>({ focus: null, image: null })
  const query = useInfiniteQuery<Catalog, ApiRequestError>({
    queryKey: ['assets-container-images', queryArgs],
    queryFn: ({ pageParam }) => api.get(`/api/assets/container-images${buildQuery({ ...queryArgs, limit: PAGE_SIZE, offset: Number(pageParam) })}`),
    initialPageParam: 0,
    getNextPageParam: (last, pages) => {
      const loaded = pages.reduce((sum, page) => sum + page.items.length, 0)
      return last.items.length && loaded < last.total ? loaded : undefined
    },
    refetchInterval: 60_000,
  })
  const items = useMemo(() => query.data?.pages.flatMap((p) => p.items) ?? [], [query.data])
  const first = query.data?.pages[0]
  const total = first?.total ?? 0
  const focusedImage: ImageRef | null = focusedId ? items.find((i) => i.source === sources[0] && i.id === focusedId) ?? { id: focusedId, source: sources[0], title: `Образ #${focusedId}` } : null
  const selectedImage = selection.focus === focusedKey ? selection.image : focusedImage
  const openImage = selectedImage ? items.find((i) => i.source === selectedImage.source && i.id === selectedImage.id) ?? selectedImage : null
  const open = (image: ImageRef | null) => setSelection({ focus: focusedKey, image })
  const urlKey = params.toString()
  useEffect(() => { setSelectedIndex(0) }, [urlKey])

  function update(next: URLSearchParams, replace = false) {
    setSelection({ focus: null, image: null })
    navigate(`/assets/container-images${next.size ? `?${next}` : ''}`, { replace })
  }
  function toggle(key: 'source' | 'status', value: string) {
    const next = new URLSearchParams(params)
    next.delete('image')
    const values: string[] = key === 'source' ? sources : states
    const picked = values.includes(value) ? values.filter((v) => v !== value) : [...values, value]
    next.delete(key)
    picked.forEach((v) => next.append(key, v))
    update(next)
  }
  function clearAll() { update(new URLSearchParams()) }
  const chips: FilterChip[] = [
    ...sources.map((v) => ({ label: `Источник: ${SOURCES[v]}`, clear: () => toggle('source', v) })),
    ...states.map((v) => ({ label: `Использование: ${STATES[v]}`, clear: () => toggle('status', v) })),
    ...(focusedId ? [{ label: `Образ #${focusedId}`, clear: () => { const next = new URLSearchParams(params); next.delete('image'); update(next) } }] : []),
  ]
  const hasFilters = chips.length > 0 || search !== ''
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (openImage) return
      if (e.key === 'Escape') { if (document.activeElement instanceof HTMLElement) document.activeElement.blur(); return }
      const target = e.target
      if (target instanceof HTMLElement && (['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName) || target.isContentEditable || target.getAttribute('role') === 'separator')) return
      if (e.key === '/') { e.preventDefault(); searchRef.current?.focus() }
      if (e.key === 'j') { e.preventDefault(); setSelectedIndex((i) => Math.min(items.length - 1, i + 1)) }
      if (e.key === 'k') { e.preventDefault(); setSelectedIndex((i) => Math.max(0, i - 1)) }
      if (e.key === 'Enter' && !(target instanceof HTMLElement && target.closest('button, a, [role="button"]')) && items[selectedIndex]) { e.preventDefault(); setSelection({ focus: focusedKey, image: items[selectedIndex] }) }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [items, selectedIndex, openImage, focusedKey])

  return <div className="flex h-full min-h-0 flex-col">
    <header className="flex shrink-0 flex-wrap items-center gap-3 border-b border-grid bg-surface px-4 py-2.5">
      <h1 className="text-sm font-semibold text-text">Образы контейнеров</h1>
      <FiltersButton open={filtersPanel.open} onToggle={filtersPanel.toggle} count={chips.length} />
      <ExportButton href={exportHref('/api/assets/container-images/export', queryArgs)} total={first?.total} disabled={query.isPending || search !== q && !focusedId} />
      <div className="relative max-w-sm flex-1">
        <Search size={14} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-text-secondary" aria-hidden />
        <input ref={searchRef} value={search} onChange={(e) => { const next = new URLSearchParams(params); next.delete('image'); if (e.target.value) next.set('q', e.target.value); else next.delete('q'); update(next, true) }} maxLength={200} aria-label="Поиск образов" placeholder="Образ, тег, хеш, хост… (/)" className="w-full rounded border border-border bg-app-bg py-1.5 pr-3 pl-8 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" />
      </div>
      {hasFilters && <button type="button" onClick={clearAll} className="flex items-center gap-1.5 rounded px-2 py-1 text-xs text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"><FilterX size={13} aria-hidden /> Сбросить</button>}
      <div className="font-mono text-xs tabular-nums text-text-secondary">{first ? items.length < total ? `${items.length} из ${total}` : total : '…'}</div>
      {!filtersPanel.open && <FilterChips chips={chips} />}
    </header>
    <div className="flex min-h-0 flex-1">
      {filtersPanel.open && <div className="flex h-full w-64 shrink-0 flex-col overflow-y-auto border-r border-grid bg-surface">
        <div className="border-b border-grid px-4 py-3 text-xs text-text-secondary">Образов <span className="font-mono tabular-nums text-text">{total}</span></div>
        <FacetSection title="Источник">{SOURCE_KEYS.map((v) => <FacetRow key={v} active={sources.includes(v)} count={first?.facets?.source[v]} onClick={() => toggle('source', v)}>{SOURCES[v]}</FacetRow>)}</FacetSection>
        <FacetSection title="Использование">{STATE_KEYS.map((v) => <FacetRow key={v} active={states.includes(v)} count={first?.facets?.status[v]} onClick={() => toggle('status', v)}>{STATES[v]}</FacetRow>)}</FacetSection>
        {focusedId && <FacetSection title="Выбранный образ"><FacetRow active noCount count={undefined} onClick={() => { const next = new URLSearchParams(params); next.delete('image'); update(next) }}>Образ #{focusedId}</FacetRow></FacetSection>}
      </div>}
      <div className="flex min-w-0 flex-1 flex-col bg-app-bg">
        {first && <div className="shrink-0 border-b border-grid px-4 py-2 text-[11px] text-text-secondary">
          {first.mp_vm?.error ? <span role="alert" className="text-kind-1">{first.mp_vm.error}. {first.mp_vm.collected_at ? `Показан снимок от ${when(first.mp_vm.collected_at)}.` : 'Успешного снимка пока нет.'}</span>
            : first.mp_vm?.collected_at ? `Снимок MP VM: ${when(first.mp_vm.collected_at)} · Статусы на момент сбора.` : 'Снимок Docker ещё не получен. Он собирается при синхронизации MaxPatrol VM.'}
        </div>}
        <div className="min-h-0 flex-1">
          {query.isPending && <FullPageSpinner />}
          {query.isError && !items.length && <div className="p-6"><ErrorState message={query.error.message} onRetry={() => query.refetch()} /></div>}
          {!query.isPending && !query.isError && !items.length && <div className="p-6"><EmptyState icon={FilterX} title={hasFilters ? 'Ничего не найдено' : 'Образов ещё нет'} description={hasFilters ? 'Ни один образ не подходит под фильтры.' : 'Образы появятся после синхронизации Harbor и MaxPatrol VM.'} /></div>}
          {!!items.length && <ImagesTable items={items} selectedIndex={selectedIndex} onSelectIndex={setSelectedIndex} onOpen={open} onReachEnd={query.hasNextPage && !query.isError ? () => { if (!query.isFetching) query.fetchNextPage() } : undefined} />}
        </div>
        {query.isFetchingNextPage && <p role="status" className="px-4 py-2 text-xs text-text-secondary">Загрузка образов…</p>}
        {query.isError && !!items.length && <div className="p-3"><ErrorState message={query.error.message} onRetry={() => query.isFetchNextPageError ? query.fetchNextPage() : query.refetch()} /></div>}
      </div>
    </div>
    {openImage && <ImageDrawer image={openImage} onClose={() => open(null)} />}
  </div>
}
