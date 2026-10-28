import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { ChevronRight, FilterX, Network as NetworkIcon, Plus, Search } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useNetworkList } from '@/modules/assets/api/queries'
import {
  NETWORK_ORIGIN_LABELS,
  NETWORK_ORIGINS,
  num,
  PLACEMENT_LABELS,
  PLACEMENTS,
  ZONE_SOURCE_LABELS,
  ZONE_SOURCES,
  type NetworkItem,
  type NetworkList,
  type NetworkOrigin,
  type NetworksQuery,
  type Placement,
  type ZoneSource,
} from '@/modules/assets/api/types'
import { Button } from '@/components/ui/Button'
import { clickableRow, ROW_FOCUS } from '@/components/ui/clickableRow'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { useVirtualRows } from '@/hooks/useVirtualRows'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { Link, useRouter, useSearchParams } from '@/lib/router'
import { ExportButton } from '@/platform/filters/ExportButton'
import { exportHref } from '@/platform/filters/exportHref'
import { FiltersButton, FilterChips, type FilterChip } from '@/platform/filters/FiltersBar'
import { useFiltersPanel } from '@/platform/filters/useFiltersPanel'
import { facetValues, useRememberedFacets, type FacetValue } from '@/platform/filters/useRememberedFacets'
import { ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'
import { fromWire, listFrom, toggleValue, toWire, valueChips } from '@/platform/findings/facets'
import { FacetRow, FacetSection } from './AssetsPage'
import { NetworkDrawer } from './NetworkDrawer'
import { ZoneRulesPanel } from './ZoneRulesPanel'

const ROW_HEIGHT = 40

// Колонки — те же, что у выгрузки /networks/export, в том же порядке.
const NETWORK_COLUMNS: ColumnDef[] = [
  { key: 'cidr', label: 'CIDR', width: 152 },
  { key: 'title', label: 'Название', width: 200, flex: true },
  { key: 'zone', label: 'Группа', width: 140 },
  { key: 'placement', label: 'Расположение', width: 132 },
  { key: 'vlan', label: 'VLAN', width: 64, align: 'right' },
  { key: 'site', label: 'Площадка', width: 120 },
  { key: 'tags', label: 'Теги', width: 200 },
  { key: 'assets', label: 'Активов', width: 80, align: 'right' },
  { key: 'open', label: 'Открыть', width: 32, resizable: false },
]
const FILTERS_PAGE = 'assets-networks'

/** Внутри страницы «не задано» — ''; в запрос уходит как `-` (toWire). */
interface Filters {
  zone?: string[]
  placement?: Placement[]
  zone_source?: ZoneSource[]
  origin?: NetworkOrigin[]
}
type Facets = NonNullable<NetworkList['facets']>

const has = <T extends string>(list: readonly T[] | undefined, value: T) => list?.includes(value) ?? false
const zoneLabel = (z: string) => z || 'без группы'

function isTypingTarget(el: EventTarget | null): boolean {
  return el instanceof HTMLElement && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT' || el.isContentEditable)
}

/** Значения фильтра из ссылки: `-` — не задано; чужие значения отбрасываются. */
function wireFrom<T extends string>(params: URLSearchParams, key: string, allowed?: readonly T[]): T[] | undefined {
  const list = fromWire(listFrom(params, key))?.filter((v): v is T => !allowed || (allowed as readonly string[]).includes(v))
  return list?.length ? list : undefined
}

function NetworkFacetPanel({ facets, zones, filters, onToggle, total }: {
  facets: Facets | null
  /** Группы, которые панель уже показывала (ушедшие в ноль — с 0); считает страница. */
  zones: FacetValue[]
  filters: Filters
  onToggle: <K extends keyof Filters>(key: K, value: Filters[K]) => void
  total: number
}) {
  const pick = <K extends keyof Filters>(key: K, value: NonNullable<Filters[K]>[number]) =>
    onToggle(key, toggleValue(filters[key] as (typeof value)[] | undefined, value) as Filters[K])
  return (
    <div className="flex h-full w-64 shrink-0 flex-col overflow-y-auto border-r border-grid bg-surface">
      <div className="border-b border-grid px-4 py-3 text-xs text-text-secondary">Сетей <span className="font-mono tabular-nums text-text">{num(total)}</span></div>
      {zones.length > 0 && (
        <FacetSection title="Группа сетей">
          {zones.map(({ value: z, count }) => (
            <FacetRow key={z} active={has(filters.zone, z)} count={count} onClick={() => pick('zone', z)}>{zoneLabel(z)}</FacetRow>
          ))}
        </FacetSection>
      )}
      <FacetSection title="Расположение">
        {PLACEMENTS.map((p) => (
          <FacetRow key={p} active={has(filters.placement, p)} count={facets?.placement[p]} onClick={() => pick('placement', p)}>{PLACEMENT_LABELS[p]}</FacetRow>
        ))}
      </FacetSection>
      <FacetSection title="Источник группы">
        {ZONE_SOURCES.map((s) => (
          <FacetRow key={s} active={has(filters.zone_source, s)} count={facets?.zone_source[s]} onClick={() => pick('zone_source', s)}>{ZONE_SOURCE_LABELS[s]}</FacetRow>
        ))}
      </FacetSection>
      <FacetSection title="Откуда сеть">
        {NETWORK_ORIGINS.map((o) => (
          <FacetRow key={o} active={has(filters.origin, o)} count={facets?.origin[o]} onClick={() => pick('origin', o)}>{NETWORK_ORIGIN_LABELS[o]}</FacetRow>
        ))}
      </FacetSection>
    </div>
  )
}

function NetworksTable({ items, selectedIndex, onSelectIndex, onOpen, onReachEnd }: {
  items: NetworkItem[]
  selectedIndex: number
  onSelectIndex: (i: number) => void
  onOpen: (i: number) => void
  onReachEnd?: () => void
}) {
  const { parentRef, rows, totalSize } = useVirtualRows(items.length, ROW_HEIGHT, selectedIndex, onReachEnd)
  const cols = useColumnWidths('assets-networks-list-columns', NETWORK_COLUMNS)
  return (
    <div ref={parentRef} data-col-resize-root className="h-full overflow-auto">
      <div className="sticky top-0 z-10 grid border-b border-grid bg-surface text-[11px] tracking-wide text-text-secondary uppercase" style={cols.gridStyle}>
        <ResizableHeader cols={cols} as="div" className="px-2 py-2" content={{ open: <span className="sr-only">Открыть</span> }} />
      </div>
      <div style={{ height: totalSize, position: 'relative' }}>
        {rows.map((v) => {
          const n = items[v.index]
          const selected = v.index === selectedIndex
          const tags = [...n.tags, ...n.implicit_tags.filter((t) => !n.tags.includes(t))]
          return (
            <div key={n.id} {...clickableRow(() => { onSelectIndex(v.index); onOpen(v.index) })} className={cn(ROW_FOCUS, 'absolute top-0 left-0 grid w-full cursor-pointer items-center border-b border-grid text-xs', selected ? 'bg-row-selected' : 'hover:bg-row-hover')} style={{ ...cols.gridStyle, height: ROW_HEIGHT, transform: `translateY(${v.start}px)` }}>
              <div className="min-w-0 truncate px-2 font-mono text-text" title={n.cidr}>{n.cidr}</div>
              <div className="flex min-w-0 items-center gap-1 px-2">
                <span className="min-w-0 truncate text-text" title={n.title}>{n.title || '—'}</span>
                {n.origin === 'racktables' && <span className="shrink-0 rounded border border-grid px-1 text-[10px] text-text-secondary">RT</span>}
              </div>
              <div className="min-w-0 truncate px-2 text-text-secondary" title={n.zone ? `${n.zone_title || n.zone} · ${ZONE_SOURCE_LABELS[n.zone_source]}` : undefined}>
                {n.zone ?? '—'}{n.zone && n.zone_source === 'manual' && <span className="ml-1 text-[10px]">вручную</span>}
              </div>
              <div className="min-w-0 truncate px-2 text-text-secondary">
                {n.placement ? PLACEMENT_LABELS[n.placement] : '—'}{n.internet_facing && <span className="ml-1 text-[10px] text-kind-1" title="доступна из интернета">интернет</span>}
              </div>
              <div className="min-w-0 truncate px-2 text-right font-mono tabular-nums text-text-secondary">{n.vlan ?? '—'}</div>
              <div className="min-w-0 truncate px-2 text-text-secondary" title={n.site || undefined}>{n.site || '—'}</div>
              <div className="min-w-0 truncate px-2 text-text-secondary" title={tags.join(', ') || undefined}>{tags.join(', ') || '—'}</div>
              <div className="min-w-0 truncate px-2 text-right font-mono tabular-nums">
                {/* Ссылка в строке-кнопке: щелчок ведёт в список активов сети, а не в карточку. */}
                <span onClick={(e) => e.stopPropagation()}><Link to={`/assets/list?network_id=${n.id}`} className="text-text hover:text-primary hover:underline">{num(n.assets)}</Link></span>
              </div>
              <div className="flex justify-end pr-2"><ChevronRight size={14} className="shrink-0 text-text-secondary/40" aria-hidden /></div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

/** Вкладка «Сети»: поиск по адресу, имени, тегу и VLAN, фасеты, список по страницам, карточка сбоку. */
function NetworksTab({ drawerOpen, onOpen, onCreate, onCloseDrawer }: { drawerOpen: boolean; onOpen: (id: number) => void; onCreate: () => void; onCloseDrawer: () => void }) {
  const params = useSearchParams()
  const { admin } = useCan()
  const [filters, setFilters] = useState<Filters>(() => ({
    zone: wireFrom(params, 'zone'),
    placement: wireFrom<Placement>(params, 'placement', PLACEMENTS),
    zone_source: wireFrom<ZoneSource>(params, 'zone_source', ZONE_SOURCES),
    origin: wireFrom<NetworkOrigin>(params, 'origin', NETWORK_ORIGINS),
  }))
  const [searchInput, setSearchInput] = useState(params.get('q') ?? '')
  const q = useDebouncedValue(searchInput.trim(), 250)
  const [selectedIndex, setSelectedIndex] = useState(0)
  const searchRef = useRef<HTMLInputElement>(null)
  const filtersPanel = useFiltersPanel(FILTERS_PAGE)

  const queryArgs = useMemo<NetworksQuery>(() => ({
    q: q || undefined, zone: toWire(filters.zone), placement: toWire(filters.placement), zone_source: toWire(filters.zone_source), origin: toWire(filters.origin),
  }), [filters, q])
  const query = useNetworkList(queryArgs)
  const items = useMemo(() => query.data?.pages.flatMap((p) => p.items) ?? [], [query.data])
  const first = query.data?.pages[0]
  const total = first?.total ?? 0
  // Группы считаются по отфильтрованному набору: ушедшие в ноль страница помнит, иначе вторую группу не выбрать.
  const zones = useRememberedFacets(first?.facets ? { zone: facetValues(first.facets.zone) } : undefined).zone ?? []
  useEffect(() => { setSelectedIndex(0) }, [queryArgs])
  const selected: NetworkItem | null = items[selectedIndex] ?? null

  function toggle<K extends keyof Filters>(key: K, value: Filters[K]) { setFilters((prev) => ({ ...prev, [key]: value })) }
  function clearAll() { setFilters({}); setSearchInput('') }
  const chips: FilterChip[] = [
    ...valueChips('Группа', filters.zone, zoneLabel, (v) => toggle('zone', v)),
    ...valueChips('Расположение', filters.placement, (p) => PLACEMENT_LABELS[p], (v) => toggle('placement', v)),
    ...valueChips('Источник группы', filters.zone_source, (s) => ZONE_SOURCE_LABELS[s], (v) => toggle('zone_source', v)),
    ...valueChips('Откуда', filters.origin, (o) => NETWORK_ORIGIN_LABELS[o], (v) => toggle('origin', v)),
  ]

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') { if (drawerOpen) return onCloseDrawer(); if (document.activeElement instanceof HTMLElement) document.activeElement.blur(); return }
      if (drawerOpen || isTypingTarget(e.target)) return
      if (e.key === '/') { e.preventDefault(); searchRef.current?.focus(); return }
      if (e.key === 'j') { e.preventDefault(); setSelectedIndex((i) => Math.min(items.length - 1, i + 1)); return }
      if (e.key === 'k') { e.preventDefault(); setSelectedIndex((i) => Math.max(0, i - 1)); return }
      // Enter на ссылке «активов» в строке — её собственное действие, а не карточка выбранной сети.
      if (e.key === 'Enter' && selected && !(e.target instanceof Element && e.target.closest('a, button'))) { e.preventDefault(); onOpen(selected.id) }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [items.length, selected, drawerOpen, onOpen, onCloseDrawer])

  const hasFilters = Object.values(filters).some((v) => v !== undefined) || q !== ''
  const errorMessage = query.error instanceof ApiRequestError ? query.error.message : query.isError ? 'Не удалось загрузить сети' : null

  return (
    <>
      <div className="flex shrink-0 flex-wrap items-center gap-3 border-b border-grid bg-surface px-4 py-2">
        <FiltersButton open={filtersPanel.open} onToggle={filtersPanel.toggle} count={chips.length} />
        <ExportButton href={exportHref('/api/assets/networks/export', queryArgs)} total={first?.total} disabled={query.isLoading} />
        <div className="relative max-w-sm flex-1">
          <Search size={14} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-text-secondary" aria-hidden />
          <input ref={searchRef} value={searchInput} onChange={(e) => setSearchInput(e.target.value)} maxLength={200} placeholder="Адрес, CIDR, имя, тег, VLAN… (/)" className="w-full rounded border border-border bg-app-bg py-1.5 pr-3 pl-8 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" />
        </div>
        {hasFilters && <button type="button" onClick={clearAll} className="flex items-center gap-1.5 rounded px-2 py-1 text-xs text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"><FilterX size={13} aria-hidden /> Сбросить</button>}
        <div className="font-mono text-xs tabular-nums text-text-secondary">{query.data ? (items.length < total ? `${num(items.length)} из ${num(total)}` : num(total)) : '…'}</div>
        {admin && <Button className="ml-auto" onClick={onCreate}><Plus size={13} aria-hidden /> Добавить сеть</Button>}
        {!filtersPanel.open && <FilterChips chips={chips} />}
      </div>
      <div className="flex min-h-0 flex-1">
        {filtersPanel.open && <NetworkFacetPanel facets={first?.facets ?? null} zones={zones} filters={filters} onToggle={toggle} total={total} />}
        <div className="flex min-w-0 flex-1 flex-col bg-app-bg">
          <div className="min-h-0 flex-1">
            {query.isLoading && <FullPageSpinner />}
            {errorMessage && <div className="p-6"><ErrorState message={errorMessage} onRetry={() => query.refetch()} /></div>}
            {!query.isLoading && !errorMessage && items.length === 0 && (
              <div className="p-6">
                <EmptyState
                  icon={hasFilters ? FilterX : NetworkIcon}
                  title={hasFilters ? 'Ничего не найдено' : 'Сетей ещё нет'}
                  description={hasFilters ? 'Ни одна сеть не подходит под поиск и фильтры.' : 'Опишите сети вручную или подключите RackTables в настройках модуля: активы привяжутся к самой узкой сети, содержащей их адрес.'}
                />
              </div>
            )}
            {!query.isLoading && !errorMessage && items.length > 0 && (
              <NetworksTable items={items} selectedIndex={selectedIndex} onSelectIndex={setSelectedIndex} onOpen={(i) => onOpen(items[i].id)} onReachEnd={() => { if (query.hasNextPage && !query.isFetchingNextPage) query.fetchNextPage() }} />
            )}
          </div>
        </div>
      </div>
    </>
  )
}

/**
 * Сети: вкладка списка (поиск, фасеты, карточка сбоку) и вкладка «Правила групп». Ссылки: `?id=<id>` открывает карточку
 * сети, `?new=<cidr>` — карточку новой сети (из карточки актива без сети), `?tab=rules` — правила.
 */
export function NetworksPage() {
  const params = useSearchParams()
  const { navigate } = useRouter()
  const [tab, setTab] = useState<'list' | 'rules'>(() => (params.get('tab') === 'rules' ? 'rules' : 'list'))
  const [openId, setOpenId] = useState<number | null>(() => (Number(params.get('id')) > 0 ? Number(params.get('id')) : null))
  // Не null — открыта карточка новой сети с этим CIDR (ссылка «создать сеть» из карточки актива или кнопка).
  const [newCidr, setNewCidr] = useState<string | null>(() => params.get('new'))
  const openCard = useCallback((id: number) => { setNewCidr(null); setOpenId(id) }, [])
  const closeDrawer = useCallback(() => { setNewCidr(null); setOpenId(null) }, [])
  // Карточка по ссылке открывается один раз: параметры снимаются, и закрытая карточка не откроется снова при обновлении.
  useEffect(() => {
    if (!params.has('id') && !params.has('new')) return
    const rest = new URLSearchParams(params)
    rest.delete('id')
    rest.delete('new')
    navigate(`/assets/networks${rest.size ? `?${rest}` : ''}`, { replace: true })
  }, [params, navigate])
  const tabClass = (on: boolean) => cn('rounded px-2 py-1 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring', on ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text')

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex shrink-0 items-center gap-3 border-b border-grid bg-surface px-4 py-2.5">
        <h1 className="text-sm font-semibold text-text">Сети</h1>
        <div role="tablist" className="flex gap-1">
          <button type="button" role="tab" aria-selected={tab === 'list'} className={tabClass(tab === 'list')} onClick={() => setTab('list')}>Сети</button>
          <button type="button" role="tab" aria-selected={tab === 'rules'} className={tabClass(tab === 'rules')} onClick={() => setTab('rules')}>Правила групп</button>
        </div>
      </header>
      {tab === 'list'
        ? <NetworksTab drawerOpen={openId !== null || newCidr !== null} onOpen={openCard} onCreate={() => { setOpenId(null); setNewCidr('') }} onCloseDrawer={closeDrawer} />
        : <div className="min-h-0 flex-1 bg-app-bg"><ZoneRulesPanel /></div>}
      <NetworkDrawer networkId={openId} newCidr={newCidr} onClose={closeDrawer} onOpen={openCard} />
    </div>
  )
}
