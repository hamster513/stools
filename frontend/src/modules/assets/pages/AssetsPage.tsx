import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { ChevronRight, FilterX, Search } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useAssetIds, useAssets, useBulkUpdate, useNetworks } from '@/modules/assets/api/queries'
import {
  ANY_CODE_LABEL,
  CODE_LABELS,
  CODES,
  CRITICALITIES,
  CRITICALITY_LABELS,
  SOURCE_LABELS,
  SOURCES,
  type AssetItem,
  type AssetsFacets,
  type AssetSource,
  type AssetsQuery,
  type CodeFilter,
  type Criticality,
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
import { useRouter, useSearchParams } from '@/lib/router'
import { FiltersButton, FilterChips, type FilterChip } from '@/platform/filters/FiltersBar'
import { useFiltersPanel } from '@/platform/filters/useFiltersPanel'
import { AssetDrawer } from './AssetDrawer'

const ROW_HEIGHT = 40
/** Ключ панели фильтров у общих фильтров платформы (useFiltersPanel). */
const FILTERS_PAGE = 'assets-list'

/** Открытость панели жила под своим ключом до перехода на общие фильтры: переносится один раз. */
function migrateFiltersOpen() {
  const old = 'stools-assets-filters-open'
  try {
    const value = localStorage.getItem(old)
    if (value === null) return
    localStorage.setItem(`stools-filters-open:${FILTERS_PAGE}`, value)
    localStorage.removeItem(old)
  } catch {
    // Хранилище недоступно — панель просто начнёт свёрнутой.
  }
}
migrateFiltersOpen()

type Filters = Omit<AssetsQuery, 'q' | 'port' | 'tag'>

function isTypingTarget(el: EventTarget | null): boolean {
  return el instanceof HTMLElement && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT' || el.isContentEditable)
}

function day(iso: string | null): string {
  return iso ? new Date(iso).toLocaleDateString('ru-RU') : '—'
}

function FacetRow({ active, count, onClick, children }: { active: boolean; count: number | undefined; onClick: () => void; children: ReactNode }) {
  return (
    <button type="button" onClick={onClick} aria-pressed={active} className={cn('flex w-full items-center justify-between gap-2 rounded px-2 py-1.5 text-left text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring', active ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text')}>
      <span className="min-w-0 flex-1 truncate">{children}</span>
      <span className="font-mono text-[11px] tabular-nums text-text-secondary">{count ?? 0}</span>
    </button>
  )
}

function FacetSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="border-b border-grid px-2 py-3">
      <div className="mb-1.5 px-2 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">{title}</div>
      <div className="flex flex-col gap-0.5">{children}</div>
    </div>
  )
}

const INPUT_BASE = 'rounded border border-border bg-app-bg px-2 py-1 text-xs text-text placeholder:text-text-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'
const INPUT = `w-full ${INPUT_BASE}`

function FacetPanel({ facets, filters, onToggle, total, port, onPort, tag, onTag }: {
  facets: AssetsFacets | null
  filters: Filters
  onToggle: <K extends keyof Filters>(key: K, value: Filters[K]) => void
  total: number
  port: string
  onPort: (v: string) => void
  tag: string
  onTag: (v: string) => void
}) {
  const zones = Object.entries(facets?.zone ?? {}).sort((a, b) => b[1] - a[1])
  const networks = useNetworks()
  return (
    <div className="flex h-full w-64 shrink-0 flex-col overflow-y-auto border-r border-grid bg-surface">
      <div className="border-b border-grid px-4 py-3 text-xs text-text-secondary">Активов <span className="font-mono tabular-nums text-text">{total}</span></div>
      <FacetSection title="Расхождения">
        <FacetRow active={filters.code === 'any'} count={facets?.code.any} onClick={() => onToggle('code', filters.code === 'any' ? undefined : 'any')}>{ANY_CODE_LABEL}</FacetRow>
        {CODES.map((c) => (
          <FacetRow key={c} active={filters.code === c} count={facets?.code[c]} onClick={() => onToggle('code', filters.code === c ? undefined : c)}>{CODE_LABELS[c]}</FacetRow>
        ))}
      </FacetSection>
      <FacetSection title="Источник есть">
        {SOURCES.map((s) => (
          <FacetRow key={s} active={filters.source_has === s} count={facets?.source[s]} onClick={() => onToggle('source_has', filters.source_has === s ? undefined : s)}>{SOURCE_LABELS[s]}</FacetRow>
        ))}
      </FacetSection>
      <FacetSection title="Источника нет">
        {SOURCES.map((s) => (
          <FacetRow key={s} active={filters.source_missing === s} count={facets ? total - facets.source[s] : undefined} onClick={() => onToggle('source_missing', filters.source_missing === s ? undefined : s)}>{SOURCE_LABELS[s]}</FacetRow>
        ))}
      </FacetSection>
      <FacetSection title="Критичность">
        {([...CRITICALITIES, 'none'] as const).map((c) => (
          <FacetRow key={c} active={filters.criticality === c} count={facets?.criticality[c]} onClick={() => onToggle('criticality', filters.criticality === c ? undefined : c)}>{CRITICALITY_LABELS[c]}</FacetRow>
        ))}
      </FacetSection>
      {zones.length > 0 && (
        <FacetSection title="Зона">
          {zones.map(([z, n]) => (
            <FacetRow key={z} active={filters.zone === z} count={n} onClick={() => onToggle('zone', filters.zone === z ? undefined : z)}>{z}</FacetRow>
          ))}
        </FacetSection>
      )}
      <FacetSection title="Сеть, открытый порт и тег">
        <div className="flex flex-col gap-1.5 px-2">
          <select value={filters.network_id ?? ''} onChange={(e) => onToggle('network_id', e.target.value ? Number(e.target.value) : undefined)} aria-label="Сеть" className={INPUT}>
            <option value="">все сети</option>
            {(networks.data ?? []).map((n) => <option key={n.id} value={n.id}>{n.cidr}{n.title ? ` — ${n.title}` : ''}</option>)}
          </select>
          <input value={port} onChange={(e) => onPort(e.target.value.replace(/\D/g, ''))} inputMode="numeric" placeholder="порт, например 3389" aria-label="Открытый порт" className={INPUT} />
          <input value={tag} onChange={(e) => onTag(e.target.value)} placeholder="тег" aria-label="Тег" className={INPUT} />
        </div>
      </FacetSection>
    </div>
  )
}

function SourceBadges({ item }: { item: AssetItem }) {
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

/** `checked` — отмеченные для массового изменения (undefined — отмечать нельзя: у аудитора флажков нет). */
function AssetsTable({ items, selectedIndex, onSelectIndex, onOpen, onReachEnd, checked, onCheck, onCheckAll }: {
  items: AssetItem[]
  selectedIndex: number
  onSelectIndex: (i: number) => void
  onOpen: (i: number) => void
  onReachEnd?: () => void
  checked?: Set<number>
  onCheck: (index: number, range: boolean) => void
  onCheckAll: (on: boolean) => void
}) {
  const { parentRef, rows, totalSize } = useVirtualRows(items.length, ROW_HEIGHT, selectedIndex, onReachEnd)
  const allChecked = checked !== undefined && items.length > 0 && items.every((a) => checked.has(a.id))
  return (
    <div ref={parentRef} className="h-full overflow-auto">
      <div className="sticky top-0 z-10 flex min-w-[1100px] border-b border-grid bg-surface text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
        {checked && (
          <div className="flex w-8 shrink-0 items-center justify-center">
            <input type="checkbox" className="accent-primary" checked={allChecked} onChange={(e) => onCheckAll(e.target.checked)} aria-label="Отметить все загруженные строки" />
          </div>
        )}
        <div className="w-60 shrink-0 px-2 py-2">Имя</div>
        <div className="w-32 shrink-0 px-2 py-2">IP</div>
        <div className="w-44 shrink-0 px-2 py-2">Сеть · зона</div>
        <div className="w-48 shrink-0 px-2 py-2">ОС</div>
        <div className="w-40 shrink-0 px-2 py-2">Источники</div>
        <div className="w-28 shrink-0 px-2 py-2">Виден</div>
        <div className="w-28 shrink-0 px-2 py-2 text-right">Расхождения</div>
      </div>
      <div style={{ height: totalSize, position: 'relative' }}>
        {rows.map((v) => {
          const a = items[v.index]
          const selected = v.index === selectedIndex
          return (
            <div key={a.id} {...clickableRow(() => { onSelectIndex(v.index); onOpen(v.index) })} className={cn(ROW_FOCUS, 'absolute top-0 left-0 flex w-full min-w-[1100px] cursor-pointer items-center border-b border-grid text-xs', selected ? 'bg-row-selected' : 'hover:bg-row-hover')} style={{ height: ROW_HEIGHT, transform: `translateY(${v.start}px)` }}>
              {checked && (
                // Щелчок по флажку не открывает карточку; Shift отмечает диапазон от предыдущего флажка.
                <div className="flex h-full w-8 shrink-0 items-center justify-center" onClick={(e) => e.stopPropagation()}>
                  <input type="checkbox" className="accent-primary" checked={checked.has(a.id)} onChange={(e) => onCheck(v.index, (e.nativeEvent as MouseEvent).shiftKey)} aria-label={`Отметить ${a.name || a.fqdn || a.ip || `актив #${a.id}`}`} />
                </div>
              )}
              <div className="w-60 shrink-0 truncate px-2">
                <div className="truncate text-text" title={a.name}>{a.name || a.fqdn || a.ip || `актив #${a.id}`}</div>
                <div className="truncate text-[10px] text-text-secondary" title={a.fqdn}>{a.fqdn}</div>
              </div>
              <div className="w-32 shrink-0 truncate px-2 font-mono text-text-secondary">{a.ip || '—'}</div>
              <div className="w-44 shrink-0 truncate px-2 text-text-secondary" title={a.network?.title}>{a.network ? `${a.network.cidr}${a.network.zone ? ` · ${a.network.zone}` : ''}` : '—'}</div>
              <div className="w-48 shrink-0 truncate px-2 text-text-secondary" title={a.os}>{a.os || '—'}</div>
              <div className="w-40 shrink-0 px-2"><SourceBadges item={a} /></div>
              <div className="w-28 shrink-0 truncate px-2 text-text-secondary">{day(a.last_seen)}</div>
              <div className={cn('w-28 shrink-0 truncate px-2 text-right font-mono tabular-nums', a.discrepancy_count > 0 ? 'text-risk-high' : 'text-text-secondary')} title={a.codes.map((c) => CODE_LABELS[c]).join(', ')}>
                {a.discrepancy_count}
              </div>
              <ChevronRight size={14} className="mr-2 ml-auto shrink-0 text-text-secondary/40" aria-hidden />
            </div>
          )
        })}
      </div>
    </div>
  )
}

const split = (text: string) => text.split(',').map((t) => t.trim()).filter(Boolean)

/** Массовое изменение отмеченных активов: критичность и теги (добавить, снять). Заметка и сеть — только в карточке. */
function BulkBar({ ids, total, selectingAll, onSelectAll, onClear }: { ids: number[]; total: number; selectingAll: boolean; onSelectAll: () => void; onClear: () => void }) {
  const bulk = useBulkUpdate()
  // 'keep' — критичность не менять; '' — сбросить в «не задана».
  const [criticality, setCriticality] = useState<Criticality | '' | 'keep'>('keep')
  const [add, setAdd] = useState('')
  const [remove, setRemove] = useState('')
  const tagsAdd = split(add)
  const tagsRemove = split(remove)
  const nothing = criticality === 'keep' && tagsAdd.length === 0 && tagsRemove.length === 0
  function apply() {
    bulk.mutate(
      { ids, ...(criticality === 'keep' ? {} : { criticality }), tags_add: tagsAdd, tags_remove: tagsRemove },
      { onSuccess: () => { setCriticality('keep'); setAdd(''); setRemove('') } },
    )
  }
  return (
    <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-grid bg-surface px-3 py-2 text-xs">
      <span className="text-text">Отмечено <span className="font-mono tabular-nums">{ids.length}</span></span>
      {ids.length < total && <button type="button" onClick={onSelectAll} disabled={selectingAll} className="text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">{selectingAll ? 'выбираю…' : `отметить все ${total} по фильтру`}</button>}
      <select value={criticality} onChange={(e) => setCriticality(e.target.value as Criticality | '' | 'keep')} aria-label="Критичность" className={cn(INPUT_BASE, 'ml-2 w-44')}>
        <option value="keep">критичность: не менять</option>
        <option value="">критичность: {CRITICALITY_LABELS.none}</option>
        {CRITICALITIES.map((c) => <option key={c} value={c}>критичность: {CRITICALITY_LABELS[c]}</option>)}
      </select>
      <input value={add} onChange={(e) => setAdd(e.target.value)} placeholder="добавить теги, через запятую" aria-label="Добавить теги" className={cn(INPUT_BASE, 'w-52')} />
      <input value={remove} onChange={(e) => setRemove(e.target.value)} placeholder="снять теги, через запятую" aria-label="Снять теги" className={cn(INPUT_BASE, 'w-52')} />
      <Button variant="primary" disabled={nothing} loading={bulk.isPending} onClick={apply}>Применить</Button>
      <Button variant="ghost" onClick={onClear}>Снять отметки</Button>
      {bulk.error && <span className="text-kind-1">{bulk.error.message}</span>}
      {bulk.isSuccess && !bulk.isPending && <span className="text-text-secondary">изменено активов: {bulk.data.updated}</span>}
    </div>
  )
}

/**
 * Реестр активов: таблица с фасетами слева, карточка справа. Адрес задаёт начальные фильтры — сюда ведут
 * ссылки обзора; `?asset=<id>` сразу открывает карточку — так ведут ссылки «в Assets» из антивируса и VM.
 */
export function AssetsPage() {
  const params = useSearchParams()
  const { navigate } = useRouter()
  const [filters, setFilters] = useState<Filters>(() => ({
    source_has: (params.get('source_has') as AssetSource | null) ?? undefined,
    source_missing: (params.get('source_missing') as AssetSource | null) ?? undefined,
    code: (params.get('code') as CodeFilter | null) ?? undefined,
    zone: params.get('zone') ?? undefined,
    criticality: (params.get('criticality') as Criticality | 'none' | null) ?? undefined,
    network_id: params.get('network_id') ? Number(params.get('network_id')) : undefined,
  }))
  const [searchInput, setSearchInput] = useState(params.get('q') ?? '')
  const [portInput, setPortInput] = useState(params.get('port') ?? '')
  const [tagInput, setTagInput] = useState(params.get('tag') ?? '')
  const q = useDebouncedValue(searchInput, 250)
  const port = useDebouncedValue(portInput, 250)
  const tag = useDebouncedValue(tagInput, 250)
  const [selectedIndex, setSelectedIndex] = useState(0)
  const [openId, setOpenId] = useState<number | null>(() => (Number(params.get('asset')) > 0 ? Number(params.get('asset')) : null))
  const searchRef = useRef<HTMLInputElement>(null)
  const { write } = useCan()
  const networks = useNetworks()
  const filtersPanel = useFiltersPanel(FILTERS_PAGE)
  const [checked, setChecked] = useState<Set<number>>(() => new Set())
  const lastChecked = useRef<number | null>(null)
  const allIds = useAssetIds()

  const queryArgs = useMemo<AssetsQuery>(
    () => ({ ...filters, q: q || undefined, port: port ? Number(port) : undefined, tag: tag.trim() || undefined }),
    [filters, q, port, tag],
  )
  const query = useAssets(queryArgs)
  const items = useMemo(() => query.data?.pages.flatMap((p) => p.items) ?? [], [query.data])
  const first = query.data?.pages[0]
  const total = first?.total ?? 0
  // Новый фильтр — другой список: курсор в начало, отметки сняты.
  useEffect(() => { setSelectedIndex(0); setChecked(new Set()); lastChecked.current = null }, [queryArgs])
  const selected: AssetItem | null = items[selectedIndex] ?? null

  function toggle<K extends keyof Filters>(key: K, value: Filters[K]) { setFilters((prev) => ({ ...prev, [key]: value })) }
  function clearAll() { setFilters({}); setSearchInput(''); setPortInput(''); setTagInput('') }
  function check(index: number, range: boolean) {
    const from = range && lastChecked.current !== null ? lastChecked.current : index
    const on = !checked.has(items[index].id)
    setChecked((prev) => {
      const next = new Set(prev)
      for (let i = Math.min(from, index); i <= Math.max(from, index); i++) { if (on) next.add(items[i].id); else next.delete(items[i].id) }
      return next
    })
    lastChecked.current = index
  }
  function checkAll(on: boolean) { setChecked(on ? new Set(items.map((a) => a.id)) : new Set()); lastChecked.current = null }
  // Что выбрано, пока панель свёрнута: фильтр из ссылки обзора не должен действовать незаметно.
  const chips: FilterChip[] = []
  if (filters.code) chips.push({ label: filters.code === 'any' ? ANY_CODE_LABEL : CODE_LABELS[filters.code], clear: () => toggle('code', undefined) })
  if (filters.source_has) chips.push({ label: `есть в ${SOURCE_LABELS[filters.source_has]}`, clear: () => toggle('source_has', undefined) })
  if (filters.source_missing) chips.push({ label: `нет в ${SOURCE_LABELS[filters.source_missing]}`, clear: () => toggle('source_missing', undefined) })
  if (filters.criticality) chips.push({ label: `критичность ${CRITICALITY_LABELS[filters.criticality]}`, clear: () => toggle('criticality', undefined) })
  if (filters.zone) chips.push({ label: `зона ${filters.zone}`, clear: () => toggle('zone', undefined) })
  if (filters.network_id !== undefined) chips.push({ label: `сеть ${networks.data?.find((n) => n.id === filters.network_id)?.cidr ?? `#${filters.network_id}`}`, clear: () => toggle('network_id', undefined) })
  if (portInput) chips.push({ label: `порт ${portInput}`, clear: () => setPortInput('') })
  if (tagInput.trim()) chips.push({ label: `тег ${tagInput.trim()}`, clear: () => setTagInput('') })
  // Карточка по ссылке открывается один раз: параметр снимается, и закрытая карточка не откроется снова при обновлении страницы.
  useEffect(() => {
    if (!params.has('asset')) return
    const rest = new URLSearchParams(params)
    rest.delete('asset')
    navigate(`/assets/list${rest.size ? `?${rest}` : ''}`, { replace: true })
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

  const hasFilters = Object.values(filters).some((v) => v !== undefined) || q !== '' || port !== '' || tag !== ''
  const errorMessage = query.error instanceof ApiRequestError ? query.error.message : query.isError ? 'Не удалось загрузить активы' : null

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex shrink-0 flex-wrap items-center gap-3 border-b border-grid bg-surface px-4 py-2.5">
        <h1 className="text-sm font-semibold text-text">Активы</h1>
        <FiltersButton open={filtersPanel.open} onToggle={filtersPanel.toggle} count={chips.length} />
        <div className="relative max-w-sm flex-1">
          <Search size={14} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-text-secondary" aria-hidden />
          <input ref={searchRef} value={searchInput} onChange={(e) => setSearchInput(e.target.value)} placeholder="Имя, FQDN, IP, ОС… (/)" className="w-full rounded border border-border bg-app-bg py-1.5 pr-3 pl-8 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" />
        </div>
        {hasFilters && <button type="button" onClick={clearAll} className="flex items-center gap-1.5 rounded px-2 py-1 text-xs text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"><FilterX size={13} aria-hidden /> Сбросить</button>}
        <div className="font-mono text-xs tabular-nums text-text-secondary">{query.data ? (items.length < total ? `${items.length} из ${total}` : total) : '…'}</div>
        {!filtersPanel.open && <FilterChips chips={chips} />}
      </header>
      <div className="flex min-h-0 flex-1">
        {filtersPanel.open && <FacetPanel facets={first?.facets ?? null} filters={filters} onToggle={toggle} total={total} port={portInput} onPort={setPortInput} tag={tagInput} onTag={setTagInput} />}
        <div className="flex min-w-0 flex-1 flex-col bg-app-bg">
          {write && checked.size > 0 && (
            <BulkBar ids={[...checked]} total={total} selectingAll={allIds.isPending} onClear={() => checkAll(false)}
              onSelectAll={() => allIds.mutate(queryArgs, { onSuccess: (r) => setChecked(new Set(r.ids)) })} />
          )}
          <div className="min-h-0 flex-1">
            {query.isLoading && <FullPageSpinner />}
            {errorMessage && <div className="p-6"><ErrorState message={errorMessage} onRetry={() => query.refetch()} /></div>}
            {!query.isLoading && !errorMessage && items.length === 0 && (
              <div className="p-6">
                <EmptyState
                  icon={FilterX}
                  title={hasFilters ? 'Ничего не найдено' : 'Активов ещё нет'}
                  description={hasFilters ? 'Ни один актив не подходит под фильтры.' : 'Активы появятся после импорта в модулях VM, антивируса или AD — или после синхронизации кнопкой на обзоре и в настройках.'}
                />
              </div>
            )}
            {!query.isLoading && !errorMessage && items.length > 0 && (
              <AssetsTable items={items} selectedIndex={selectedIndex} onSelectIndex={setSelectedIndex} onOpen={(i) => setOpenId(items[i].id)} onReachEnd={() => { if (query.hasNextPage && !query.isFetchingNextPage) query.fetchNextPage() }}
                checked={write ? checked : undefined} onCheck={check} onCheckAll={checkAll} />
            )}
          </div>
        </div>
      </div>
      <AssetDrawer assetId={openId} onClose={() => setOpenId(null)} onOpenAsset={setOpenId} />
    </div>
  )
}
