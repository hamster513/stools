import { useEffect, useMemo, useRef, useState } from 'react'
import { ChevronRight, FilterX, Search } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useAsset, useGroups } from '@/modules/assets/api/queries'
import {
  GROUP_KIND_LABELS,
  GROUP_KINDS,
  GROUP_MEMBERS,
  GROUP_MEMBERS_LABELS,
  GROUP_SOURCE_LABELS,
  GROUP_SOURCES,
  GROUP_STATE_LABELS,
  GROUP_STATES,
  num,
  type GroupItem,
  type GroupKind,
  type GroupMembers,
  type GroupSource,
  type GroupsFacets,
  type GroupsQuery,
  type GroupState,
} from '@/modules/assets/api/types'
import { clickableRow, ROW_FOCUS } from '@/components/ui/clickableRow'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { useVirtualRows } from '@/hooks/useVirtualRows'
import { cn } from '@/lib/cn'
import { Link, useRouter, useSearchParams } from '@/lib/router'
import { ExportButton } from '@/platform/filters/ExportButton'
import { exportHref } from '@/platform/filters/exportHref'
import { FiltersButton, FilterChips, type FilterChip } from '@/platform/filters/FiltersBar'
import { useFiltersPanel } from '@/platform/filters/useFiltersPanel'
import { ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'
import { listFrom, toggleValue, valueChips } from '@/platform/findings/facets'
import { FacetRow, FacetSection } from './AssetsPage'
import { GroupDrawer, GroupKindBadge } from './GroupDrawer'

const ROW_HEIGHT = 40

// Колонки — те же, что у выгрузки /groups/export, в том же порядке.
const GROUP_COLUMNS: ColumnDef[] = [
  { key: 'name', label: 'Имя', width: 220, flex: true },
  { key: 'domain', label: 'Домен / компьютер', width: 176 },
  { key: 'kind', label: 'Вид', width: 140 },
  { key: 'members', label: 'Участников', width: 96, align: 'right' },
  { key: 'sources', label: 'Источники', width: 88 },
  { key: 'sid', label: 'SID', width: 240 },
  { key: 'description', label: 'Описание', width: 220 },
  { key: 'open', label: 'Открыть', width: 32, resizable: false },
]
const FILTERS_PAGE = 'assets-groups'

type Filters = Omit<GroupsQuery, 'q'>
type MultiKey = Exclude<keyof Filters, 'host_id'>

const has = <T extends string | number>(list: readonly T[] | undefined, value: T) => list?.includes(value) ?? false

function isTypingTarget(el: EventTarget | null): boolean {
  return el instanceof HTMLElement && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT' || el.isContentEditable)
}

/** Хосты из ссылки «локальные группы хоста»: номера (ключ повторяется); не числа отбрасываются. */
function hostIdsFrom(params: URLSearchParams): number[] | undefined {
  const ids = listFrom(params, 'host_id')?.map(Number).filter((n) => Number.isInteger(n) && n > 0)
  return ids?.length ? ids : undefined
}

function GroupFacetPanel({ facets, filters, onToggle, total, hostLabel }: {
  facets: GroupsFacets | null
  filters: Filters
  onToggle: <K extends keyof Filters>(key: K, value: Filters[K]) => void
  total: number
  hostLabel: (id: number) => string
}) {
  const pick = <K extends MultiKey>(key: K, value: NonNullable<Filters[K]>[number]) =>
    onToggle(key, toggleValue(filters[key] as (typeof value)[] | undefined, value) as Filters[K])
  return (
    <div className="flex h-full w-64 shrink-0 flex-col overflow-y-auto border-r border-grid bg-surface">
      <div className="border-b border-grid px-4 py-3 text-xs text-text-secondary">Групп <span className="font-mono tabular-nums text-text">{num(total)}</span></div>
      <FacetSection title="Вид">
        {GROUP_KINDS.map((k) => (
          <FacetRow key={k} active={has(filters.kind, k)} count={facets?.kind[k]} onClick={() => pick('kind', k)}>{GROUP_KIND_LABELS[k]}</FacetRow>
        ))}
      </FacetSection>
      <FacetSection title="Источник видит">
        {GROUP_SOURCES.map((s) => (
          <FacetRow key={s} active={has(filters.source, s)} count={facets?.source[s]} onClick={() => pick('source', s)}>{GROUP_SOURCE_LABELS[s]}</FacetRow>
        ))}
      </FacetSection>
      <FacetSection title="Участники">
        {GROUP_MEMBERS.map((m) => (
          <FacetRow key={m} active={has(filters.members, m)} count={facets?.members[m]} onClick={() => pick('members', m)}>{GROUP_MEMBERS_LABELS[m]}</FacetRow>
        ))}
      </FacetSection>
      {/* Без выбора сервер показывает только живые группы; пропавшие — выбором «пропавшие». */}
      <FacetSection title="Состояние">
        {GROUP_STATES.map((s) => (
          <FacetRow key={s} active={has(filters.state, s)} count={facets?.state[s]} onClick={() => pick('state', s)}>{GROUP_STATE_LABELS[s]}</FacetRow>
        ))}
        {!filters.state && <p className="px-2 pt-1 text-[11px] text-text-secondary">не выбрано — показаны живые</p>}
      </FacetSection>
      {/* Хост выбирается ссылкой «локальные группы хоста» из карточки актива; здесь его можно только снять. */}
      {filters.host_id && (
        <FacetSection title="Хост">
          {filters.host_id.map((id) => (
            <FacetRow key={id} active count={undefined} noCount onClick={() => onToggle('host_id', toggleValue(filters.host_id, id))}>{hostLabel(id)}</FacetRow>
          ))}
        </FacetSection>
      )}
    </div>
  )
}

function GroupsTable({ items, selectedIndex, onSelectIndex, onOpen, onReachEnd }: {
  items: GroupItem[]
  selectedIndex: number
  onSelectIndex: (i: number) => void
  onOpen: (i: number) => void
  onReachEnd?: () => void
}) {
  const { parentRef, rows, totalSize } = useVirtualRows(items.length, ROW_HEIGHT, selectedIndex, onReachEnd)
  const cols = useColumnWidths('assets-groups-columns', GROUP_COLUMNS)
  return (
    <div ref={parentRef} data-col-resize-root className="h-full overflow-auto">
      <div className="sticky top-0 z-10 grid border-b border-grid bg-surface text-[11px] tracking-wide text-text-secondary uppercase" style={cols.gridStyle}>
        <ResizableHeader cols={cols} as="div" className="px-2 py-2" content={{ open: <span className="sr-only">Открыть</span> }} />
      </div>
      <div style={{ height: totalSize, position: 'relative' }}>
        {rows.map((v) => {
          const g = items[v.index]
          const selected = v.index === selectedIndex
          return (
            <div key={g.id} {...clickableRow(() => { onSelectIndex(v.index); onOpen(v.index) })} className={cn(ROW_FOCUS, 'absolute top-0 left-0 grid w-full cursor-pointer items-center border-b border-grid text-xs', selected ? 'bg-row-selected' : 'hover:bg-row-hover', g.gone && 'opacity-60')} style={{ ...cols.gridStyle, height: ROW_HEIGHT, transform: `translateY(${v.start}px)` }}>
              <div className="min-w-0 truncate px-2 text-text" title={g.name}>{g.name || g.sid || `группа #${g.id}`}</div>
              <div className="min-w-0 truncate px-2 font-mono text-text-secondary" title={g.domain_label}>
                {g.local && g.host_asset_id !== null ? (
                  // Ссылка в строке-кнопке: щелчок не открывает карточку группы, а ведёт в карточку хоста.
                  <span onClick={(e) => e.stopPropagation()}>
                    <Link to={`/assets/list?asset=${g.host_asset_id}`} className="text-text hover:text-primary hover:underline">{g.domain_label || `актив #${g.host_asset_id}`}</Link>
                  </span>
                ) : (g.domain_label || '—')}
              </div>
              <div className="min-w-0 overflow-hidden px-2"><GroupKindBadge g={g} /></div>
              <div className="min-w-0 truncate px-2 text-right font-mono tabular-nums text-text-secondary">{num(g.members_direct)}</div>
              <div className="min-w-0 truncate px-2 font-mono text-[10px] text-text-secondary">{g.sources.map((s) => GROUP_SOURCE_LABELS[s]).join(', ') || '—'}</div>
              <div className="min-w-0 truncate px-2 font-mono text-text-secondary" title={g.sid}>{g.sid || '—'}</div>
              <div className="min-w-0 truncate px-2 text-text-secondary" title={g.description}>{g.description || '—'}</div>
              <div className="flex justify-end pr-2"><ChevronRight size={14} className="shrink-0 text-text-secondary/40" aria-hidden /></div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

/**
 * Группы как активы: доменные из AD и локальные группы хостов из VM. Таблица с фасетами слева, карточка справа.
 * `?id=<group_id>` сразу открывает карточку (ссылки из карточки пользователя), `?host_id=<id>` — локальные группы хоста.
 */
export function GroupsPage() {
  const params = useSearchParams()
  const { navigate } = useRouter()
  const [filters, setFilters] = useState<Filters>(() => ({
    kind: listFrom<GroupKind>(params, 'kind', GROUP_KINDS),
    source: listFrom<GroupSource>(params, 'source', GROUP_SOURCES),
    state: listFrom<GroupState>(params, 'state', GROUP_STATES),
    members: listFrom<GroupMembers>(params, 'members', GROUP_MEMBERS),
    host_id: hostIdsFrom(params),
  }))
  const [searchInput, setSearchInput] = useState(params.get('q') ?? '')
  const q = useDebouncedValue(searchInput, 250)
  const [selectedIndex, setSelectedIndex] = useState(0)
  const [openId, setOpenId] = useState<number | null>(() => (Number(params.get('id')) > 0 ? Number(params.get('id')) : null))
  const searchRef = useRef<HTMLInputElement>(null)
  const filtersPanel = useFiltersPanel(FILTERS_PAGE)

  const queryArgs = useMemo<GroupsQuery>(() => ({ ...filters, q: q || undefined }), [filters, q])
  const query = useGroups(queryArgs)
  const items = useMemo(() => query.data?.pages.flatMap((p) => p.items) ?? [], [query.data])
  const first = query.data?.pages[0]
  const total = first?.total ?? 0
  useEffect(() => { setSelectedIndex(0) }, [queryArgs])
  const selected: GroupItem | null = items[selectedIndex] ?? null

  // Имя хоста для чипа — одним запросом карточки, только когда хост один (так ведёт ссылка из карточки актива).
  const oneHost = filters.host_id?.length === 1 ? filters.host_id[0] : null
  const host = useAsset(oneHost)
  const hostLabel = (id: number) => (id === oneHost && host.data ? host.data.name || host.data.fqdn || host.data.ip || `актив #${id}` : `актив #${id}`)

  function toggle<K extends keyof Filters>(key: K, value: Filters[K]) { setFilters((prev) => ({ ...prev, [key]: value })) }
  function clearAll() { setFilters({}); setSearchInput('') }
  const chips: FilterChip[] = [
    ...valueChips('Хост', filters.host_id, hostLabel, (v) => toggle('host_id', v)),
    ...valueChips('Вид', filters.kind, (k) => GROUP_KIND_LABELS[k], (v) => toggle('kind', v)),
    ...valueChips('Источник видит', filters.source, (s) => GROUP_SOURCE_LABELS[s], (v) => toggle('source', v)),
    ...valueChips('Участники', filters.members, (m) => GROUP_MEMBERS_LABELS[m], (v) => toggle('members', v)),
    ...valueChips('Состояние', filters.state, (s) => GROUP_STATE_LABELS[s], (v) => toggle('state', v)),
  ]
  // Карточка по ссылке открывается один раз: параметр снимается, и закрытая карточка не откроется снова при обновлении страницы.
  useEffect(() => {
    if (!params.has('id')) return
    const rest = new URLSearchParams(params)
    rest.delete('id')
    navigate(`/assets/groups${rest.size ? `?${rest}` : ''}`, { replace: true })
  }, [params, navigate])

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') { if (openId !== null) return setOpenId(null); if (document.activeElement instanceof HTMLElement) document.activeElement.blur(); return }
      if (openId !== null || isTypingTarget(e.target)) return
      if (e.key === '/') { e.preventDefault(); searchRef.current?.focus(); return }
      if (e.key === 'j') { e.preventDefault(); setSelectedIndex((i) => Math.min(items.length - 1, i + 1)); return }
      if (e.key === 'k') { e.preventDefault(); setSelectedIndex((i) => Math.max(0, i - 1)); return }
      if (e.key === 'Enter' && selected) { e.preventDefault(); setOpenId(selected.id) }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [items.length, selected, openId])

  const hasFilters = Object.values(filters).some((v) => v !== undefined) || q !== ''
  const errorMessage = query.error instanceof ApiRequestError ? query.error.message : query.isError ? 'Не удалось загрузить группы' : null

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex shrink-0 flex-wrap items-center gap-3 border-b border-grid bg-surface px-4 py-2.5">
        <h1 className="text-sm font-semibold text-text">Группы</h1>
        <FiltersButton open={filtersPanel.open} onToggle={filtersPanel.toggle} count={chips.length} />
        <ExportButton href={exportHref('/api/assets/groups/export', queryArgs)} total={first?.total} disabled={query.isLoading} />
        <div className="relative max-w-sm flex-1">
          <Search size={14} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-text-secondary" aria-hidden />
          <input ref={searchRef} value={searchInput} onChange={(e) => setSearchInput(e.target.value)} maxLength={200} placeholder="Имя группы, SID… (/)" className="w-full rounded border border-border bg-app-bg py-1.5 pr-3 pl-8 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" />
        </div>
        {hasFilters && <button type="button" onClick={clearAll} className="flex items-center gap-1.5 rounded px-2 py-1 text-xs text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"><FilterX size={13} aria-hidden /> Сбросить</button>}
        <div className="font-mono text-xs tabular-nums text-text-secondary">{query.data ? (items.length < total ? `${num(items.length)} из ${num(total)}` : num(total)) : '…'}</div>
        {!filtersPanel.open && <FilterChips chips={chips} />}
      </header>
      <div className="flex min-h-0 flex-1">
        {filtersPanel.open && <GroupFacetPanel facets={first?.facets ?? null} filters={filters} onToggle={toggle} total={total} hostLabel={hostLabel} />}
        <div className="flex min-w-0 flex-1 flex-col bg-app-bg">
          <div className="min-h-0 flex-1">
            {query.isLoading && <FullPageSpinner />}
            {errorMessage && <div className="p-6"><ErrorState message={errorMessage} onRetry={() => query.refetch()} /></div>}
            {!query.isLoading && !errorMessage && items.length === 0 && (
              <div className="p-6">
                <EmptyState
                  icon={FilterX}
                  title={hasFilters ? 'Ничего не найдено' : 'Групп ещё нет'}
                  description={hasFilters ? 'Ни одна группа не подходит под фильтры.' : 'Группы появятся после синхронизации с модулями: доменные — из выгрузки AD, локальные группы хостов — из MaxPatrol VM.'}
                />
              </div>
            )}
            {!query.isLoading && !errorMessage && items.length > 0 && (
              <GroupsTable items={items} selectedIndex={selectedIndex} onSelectIndex={setSelectedIndex} onOpen={(i) => setOpenId(items[i].id)} onReachEnd={() => { if (query.hasNextPage && !query.isFetchingNextPage) query.fetchNextPage() }} />
            )}
          </div>
        </div>
      </div>
      <GroupDrawer groupId={openId} onClose={() => setOpenId(null)} onOpenGroup={setOpenId} />
    </div>
  )
}
