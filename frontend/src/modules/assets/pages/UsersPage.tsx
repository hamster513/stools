import { useEffect, useMemo, useRef, useState } from 'react'
import { ChevronRight, FilterX, Search } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useAsset, useUsers } from '@/modules/assets/api/queries'
import {
  ANY_CODE_LABEL,
  SOURCE_LABELS,
  USER_CODE_LABELS,
  USER_CODES,
  USER_SESSION_LABELS,
  USER_SESSIONS,
  USER_SOURCES,
  USER_STATE_LABELS,
  USER_STATES,
  userState,
  YES_NO,
  YES_NO_LABELS,
  type UserCodeFilter,
  type UserItem,
  type UserSession,
  type UserSource,
  type UsersFacets,
  type UsersQuery,
  type UserState,
  type YesNo,
} from '@/modules/assets/api/types'
import { clickableRow, ROW_FOCUS } from '@/components/ui/clickableRow'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { useVirtualRows } from '@/hooks/useVirtualRows'
import { cn } from '@/lib/cn'
import { useRouter, useSearchParams } from '@/lib/router'
import { ExportButton } from '@/platform/filters/ExportButton'
import { exportHref } from '@/platform/filters/exportHref'
import { FiltersButton, FilterChips, type FilterChip } from '@/platform/filters/FiltersBar'
import { useFiltersPanel } from '@/platform/filters/useFiltersPanel'
import { ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'
import { listFrom, toggleValue, valueChips } from '@/platform/findings/facets'
import { FacetRow, FacetSection } from './AssetsPage'
import { UserDrawer } from './UserDrawer'

const ROW_HEIGHT = 40

// Колонки — те же, что у выгрузки /users/export, в том же порядке.
const USER_COLUMNS: ColumnDef[] = [
  { key: 'sam', label: 'Учётка', width: 176 },
  { key: 'name', label: 'Имя', width: 200, flex: true },
  { key: 'upn', label: 'UPN', width: 200 },
  { key: 'domain', label: 'Домен', width: 120 },
  { key: 'local', label: 'Локальная', width: 96 },
  { key: 'state', label: 'Состояние', width: 104 },
  { key: 'privileged', label: 'Привилегированная', width: 144 },
  { key: 'sources', label: 'Источники', width: 96 },
  { key: 'hosts_active', label: 'В системе', width: 88, align: 'right' },
  { key: 'hosts_total', label: 'Хостов', width: 72, align: 'right' },
  { key: 'seen', label: 'Виден', width: 104 },
  { key: 'codes', label: 'Расхождения', width: 112, align: 'right' },
  { key: 'open', label: 'Открыть', width: 32, resizable: false },
]
const FILTERS_PAGE = 'assets-users'

type Filters = Omit<UsersQuery, 'q'>
type MultiKey = Exclude<keyof Filters, 'host_id'>

const has = <T extends string | number>(list: readonly T[] | undefined, value: T) => list?.includes(value) ?? false

function isTypingTarget(el: EventTarget | null): boolean {
  return el instanceof HTMLElement && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT' || el.isContentEditable)
}

function day(iso: string | null): string {
  return iso ? new Date(iso).toLocaleDateString('ru-RU') : '—'
}

/** Хосты из ссылки «все пользователи хоста»: номера (ключ повторяется); не числа отбрасываются. */
function hostIdsFrom(params: URLSearchParams): number[] | undefined {
  const ids = listFrom(params, 'host_id')?.map(Number).filter((n) => Number.isInteger(n) && n > 0)
  return ids?.length ? ids : undefined
}

function UserFacetPanel({ facets, filters, onToggle, total, hostLabel }: {
  facets: UsersFacets | null
  filters: Filters
  onToggle: <K extends keyof Filters>(key: K, value: Filters[K]) => void
  total: number
  hostLabel: (id: number) => string
}) {
  const pick = <K extends MultiKey>(key: K, value: NonNullable<Filters[K]>[number]) =>
    onToggle(key, toggleValue(filters[key] as (typeof value)[] | undefined, value) as Filters[K])
  return (
    <div className="flex h-full w-64 shrink-0 flex-col overflow-y-auto border-r border-grid bg-surface">
      <div className="border-b border-grid px-4 py-3 text-xs text-text-secondary">Пользователей <span className="font-mono tabular-nums text-text">{total}</span></div>
      <FacetSection title="Расхождения">
        <FacetRow active={has(filters.code, 'any')} count={facets?.code.any} onClick={() => pick('code', 'any')}>{ANY_CODE_LABEL}</FacetRow>
        {USER_CODES.map((c) => (
          <FacetRow key={c} active={has(filters.code, c)} count={facets?.code[c]} onClick={() => pick('code', c)}>{USER_CODE_LABELS[c]}</FacetRow>
        ))}
      </FacetSection>
      <FacetSection title="Источник видит">
        {USER_SOURCES.map((s) => (
          <FacetRow key={s} active={has(filters.source, s)} count={facets?.source[s]} onClick={() => pick('source', s)}>{SOURCE_LABELS[s]}</FacetRow>
        ))}
      </FacetSection>
      {/* «неизвестно» — AD учётку не видел: только KSC, локальная или домен без выгрузки. */}
      <FacetSection title="Состояние в AD">
        {USER_STATES.map((s) => (
          <FacetRow key={s} active={has(filters.state, s)} count={facets?.state[s]} onClick={() => pick('state', s)}>{USER_STATE_LABELS[s]}</FacetRow>
        ))}
      </FacetSection>
      <FacetSection title="Сеанс">
        {USER_SESSIONS.map((s) => (
          <FacetRow key={s} active={has(filters.session, s)} count={facets?.session[s]} onClick={() => pick('session', s)}>{USER_SESSION_LABELS[s]}</FacetRow>
        ))}
      </FacetSection>
      <FacetSection title="Привилегированная">
        {YES_NO.map((v) => (
          <FacetRow key={v} active={has(filters.privileged, v)} count={facets?.privileged[v]} onClick={() => pick('privileged', v)}>{YES_NO_LABELS[v]}</FacetRow>
        ))}
      </FacetSection>
      <FacetSection title="Локальная учётка">
        {YES_NO.map((v) => (
          <FacetRow key={v} active={has(filters.local, v)} count={facets?.local[v]} onClick={() => pick('local', v)}>{YES_NO_LABELS[v]}</FacetRow>
        ))}
      </FacetSection>
      {/* Хост выбирается ссылкой «все пользователи хоста» из карточки актива; здесь его можно только снять. */}
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

function SourceBadges({ item }: { item: UserItem }) {
  return (
    <div className="flex flex-wrap gap-1">
      {item.sources.map((s) => (
        <span
          key={s.source}
          title={`${SOURCE_LABELS[s.source]}: ${s.live ? 'видел' : 'больше не видит, последний раз'} ${day(s.seen_at)}${s.live && !s.fresh ? ' — давно' : ''}`}
          className={cn('rounded border px-1 py-px font-mono text-[10px]', s.fresh ? 'border-border text-text' : 'border-grid text-text-secondary/60')}
        >
          {SOURCE_LABELS[s.source]}
        </span>
      ))}
    </div>
  )
}

const STATE_TEXT = { enabled: 'text-text', disabled: 'text-risk-medium', unknown: 'text-text-secondary' } as const

function UsersTable({ items, selectedIndex, onSelectIndex, onOpen, onReachEnd }: {
  items: UserItem[]
  selectedIndex: number
  onSelectIndex: (i: number) => void
  onOpen: (i: number) => void
  onReachEnd?: () => void
}) {
  const { parentRef, rows, totalSize } = useVirtualRows(items.length, ROW_HEIGHT, selectedIndex, onReachEnd)
  const cols = useColumnWidths('assets-users-columns', USER_COLUMNS)
  return (
    <div ref={parentRef} data-col-resize-root className="h-full overflow-auto">
      <div className="sticky top-0 z-10 grid border-b border-grid bg-surface text-[11px] tracking-wide text-text-secondary uppercase" style={cols.gridStyle}>
        <ResizableHeader cols={cols} as="div" className="px-2 py-2" content={{ open: <span className="sr-only">Открыть</span> }} />
      </div>
      <div style={{ height: totalSize, position: 'relative' }}>
        {rows.map((v) => {
          const u = items[v.index]
          const selected = v.index === selectedIndex
          const state = userState(u.enabled)
          return (
            <div key={u.id} {...clickableRow(() => { onSelectIndex(v.index); onOpen(v.index) })} className={cn(ROW_FOCUS, 'absolute top-0 left-0 grid w-full cursor-pointer items-center border-b border-grid text-xs', selected ? 'bg-row-selected' : 'hover:bg-row-hover')} style={{ ...cols.gridStyle, height: ROW_HEIGHT, transform: `translateY(${v.start}px)` }}>
              <div className="min-w-0 truncate px-2 font-mono text-text" title={u.sam}>{u.sam || `пользователь #${u.id}`}</div>
              <div className="min-w-0 truncate px-2 text-text" title={u.display_name}>{u.display_name || '—'}</div>
              <div className="min-w-0 truncate px-2 font-mono text-text-secondary" title={u.upn}>{u.upn || '—'}</div>
              <div className="min-w-0 truncate px-2 font-mono text-text-secondary" title={u.domain}>{u.domain || '—'}</div>
              <div className="min-w-0 truncate px-2 text-text-secondary">{u.local ? 'да' : 'нет'}</div>
              <div className={cn('min-w-0 truncate px-2', STATE_TEXT[state])}>{USER_STATE_LABELS[state]}</div>
              <div className={cn('min-w-0 truncate px-2', u.privileged ? 'text-risk-high' : 'text-text-secondary')}>{u.privileged ? 'да' : 'нет'}</div>
              <div className="min-w-0 overflow-hidden px-2"><SourceBadges item={u} /></div>
              <div className="min-w-0 truncate px-2 text-right font-mono tabular-nums text-text-secondary">{u.hosts_active}</div>
              <div className="min-w-0 truncate px-2 text-right font-mono tabular-nums text-text-secondary">{u.hosts_total}</div>
              <div className="min-w-0 truncate px-2 text-text-secondary">{day(u.last_seen)}</div>
              <div className={cn('min-w-0 truncate px-2 text-right font-mono tabular-nums', u.codes.length > 0 ? 'text-risk-high' : 'text-text-secondary')} title={u.codes.map((c) => USER_CODE_LABELS[c]).join(', ')}>
                {u.codes.length}
              </div>
              <div className="flex justify-end pr-2"><ChevronRight size={14} className="shrink-0 text-text-secondary/40" aria-hidden /></div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

/**
 * Пользователи как активы: учётки AD и сеансы, владельцы устройств из KSC. Таблица с фасетами слева, карточка справа.
 * `?user=<id>` сразу открывает карточку (ссылки из карточки хоста), `?host_id=<id>` — пользователи этого хоста.
 */
export function UsersPage() {
  const params = useSearchParams()
  const { navigate } = useRouter()
  const [filters, setFilters] = useState<Filters>(() => ({
    source: listFrom<UserSource>(params, 'source', USER_SOURCES),
    state: listFrom<UserState>(params, 'state', USER_STATES),
    session: listFrom<UserSession>(params, 'session', USER_SESSIONS),
    local: listFrom<YesNo>(params, 'local', YES_NO),
    privileged: listFrom<YesNo>(params, 'privileged', YES_NO),
    code: listFrom<UserCodeFilter>(params, 'code', ['any', ...USER_CODES]),
    host_id: hostIdsFrom(params),
  }))
  const [searchInput, setSearchInput] = useState(params.get('q') ?? '')
  const q = useDebouncedValue(searchInput, 250)
  const [selectedIndex, setSelectedIndex] = useState(0)
  const [openId, setOpenId] = useState<number | null>(() => (Number(params.get('user')) > 0 ? Number(params.get('user')) : null))
  const searchRef = useRef<HTMLInputElement>(null)
  const filtersPanel = useFiltersPanel(FILTERS_PAGE)

  const queryArgs = useMemo<UsersQuery>(() => ({ ...filters, q: q || undefined }), [filters, q])
  const query = useUsers(queryArgs)
  const items = useMemo(() => query.data?.pages.flatMap((p) => p.items) ?? [], [query.data])
  const first = query.data?.pages[0]
  const total = first?.total ?? 0
  useEffect(() => { setSelectedIndex(0) }, [queryArgs])
  const selected: UserItem | null = items[selectedIndex] ?? null

  // Имя хоста для чипа — одним запросом карточки, только когда хост один (так ведёт ссылка из карточки актива).
  const oneHost = filters.host_id?.length === 1 ? filters.host_id[0] : null
  const host = useAsset(oneHost)
  const hostLabel = (id: number) => (id === oneHost && host.data ? host.data.name || host.data.fqdn || host.data.ip || `актив #${id}` : `актив #${id}`)

  function toggle<K extends keyof Filters>(key: K, value: Filters[K]) { setFilters((prev) => ({ ...prev, [key]: value })) }
  function clearAll() { setFilters({}); setSearchInput('') }
  const chips: FilterChip[] = [
    ...valueChips('Хост', filters.host_id, hostLabel, (v) => toggle('host_id', v)),
    ...valueChips('Расхождения', filters.code, (c) => (c === 'any' ? ANY_CODE_LABEL : USER_CODE_LABELS[c]), (v) => toggle('code', v)),
    ...valueChips('Источник видит', filters.source, (s) => SOURCE_LABELS[s], (v) => toggle('source', v)),
    ...valueChips('Состояние в AD', filters.state, (s) => USER_STATE_LABELS[s], (v) => toggle('state', v)),
    ...valueChips('Сеанс', filters.session, (s) => USER_SESSION_LABELS[s], (v) => toggle('session', v)),
    ...valueChips('Привилегированная', filters.privileged, (v) => YES_NO_LABELS[v], (v) => toggle('privileged', v)),
    ...valueChips('Локальная', filters.local, (v) => YES_NO_LABELS[v], (v) => toggle('local', v)),
  ]
  // Карточка по ссылке открывается один раз: параметр снимается, и закрытая карточка не откроется снова при обновлении страницы.
  useEffect(() => {
    if (!params.has('user')) return
    const rest = new URLSearchParams(params)
    rest.delete('user')
    navigate(`/assets/users${rest.size ? `?${rest}` : ''}`, { replace: true })
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
  const errorMessage = query.error instanceof ApiRequestError ? query.error.message : query.isError ? 'Не удалось загрузить пользователей' : null

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex shrink-0 flex-wrap items-center gap-3 border-b border-grid bg-surface px-4 py-2.5">
        <h1 className="text-sm font-semibold text-text">Пользователи</h1>
        <FiltersButton open={filtersPanel.open} onToggle={filtersPanel.toggle} count={chips.length} />
        <ExportButton href={exportHref('/api/assets/users/export', queryArgs)} total={first?.total} disabled={query.isLoading} />
        <div className="relative max-w-sm flex-1">
          <Search size={14} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-text-secondary" aria-hidden />
          <input ref={searchRef} value={searchInput} onChange={(e) => setSearchInput(e.target.value)} placeholder="Учётка, имя, UPN, SID… (/)" className="w-full rounded border border-border bg-app-bg py-1.5 pr-3 pl-8 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" />
        </div>
        {hasFilters && <button type="button" onClick={clearAll} className="flex items-center gap-1.5 rounded px-2 py-1 text-xs text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"><FilterX size={13} aria-hidden /> Сбросить</button>}
        <div className="font-mono text-xs tabular-nums text-text-secondary">{query.data ? (items.length < total ? `${items.length} из ${total}` : total) : '…'}</div>
        {!filtersPanel.open && <FilterChips chips={chips} />}
      </header>
      <div className="flex min-h-0 flex-1">
        {filtersPanel.open && <UserFacetPanel facets={first?.facets ?? null} filters={filters} onToggle={toggle} total={total} hostLabel={hostLabel} />}
        <div className="flex min-w-0 flex-1 flex-col bg-app-bg">
          <div className="min-h-0 flex-1">
            {query.isLoading && <FullPageSpinner />}
            {errorMessage && <div className="p-6"><ErrorState message={errorMessage} onRetry={() => query.refetch()} /></div>}
            {!query.isLoading && !errorMessage && items.length === 0 && (
              <div className="p-6">
                <EmptyState
                  icon={FilterX}
                  title={hasFilters ? 'Ничего не найдено' : 'Пользователей ещё нет'}
                  description={hasFilters ? 'Ни один пользователь не подходит под фильтры.' : 'Пользователи появятся после синхронизации с модулями: учётки и группы — из выгрузки AD, сеансы и владельцы устройств — из снапшота антивируса (сборщик KSC 1.4 и новее).'}
                />
              </div>
            )}
            {!query.isLoading && !errorMessage && items.length > 0 && (
              <UsersTable items={items} selectedIndex={selectedIndex} onSelectIndex={setSelectedIndex} onOpen={(i) => setOpenId(items[i].id)} onReachEnd={() => { if (query.hasNextPage && !query.isFetchingNextPage) query.fetchNextPage() }} />
            )}
          </div>
        </div>
      </div>
      <UserDrawer userId={openId} onClose={() => setOpenId(null)} onOpenUser={setOpenId} />
    </div>
  )
}
