import { useListState } from '@/hooks/useListState'
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { ChevronRight, FilterX, Search, Trash2 } from 'lucide-react'
import { ApiRequestError, buildQuery } from '@/api/client'
import { readViewState, viewOwner, writeViewState } from '@/api/listCache'
import { NETWORK_PICK_LIMIT, useAssetIds, useAssets, useBulkDelete, useBulkUpdate, useDiscrepancyBulk, useNetworkCards, useNetworkSearch } from '@/modules/assets/api/queries'
import {
  ANY_CODE_LABEL,
  CLUSTER_KINDS,
  CLUSTER_LABELS,
  CODE_LABELS,
  CODES,
  CRITICALITIES,
  CRITICALITY_LABELS,
  LAPS_LABELS,
  LAPS_VALUES,
  PLACEMENT_LABELS,
  PLACEMENTS,
  SOURCE_LABELS,
  SOURCES,
  type AssetItem,
  type AssetsFacets,
  type AssetSource,
  type AssetsQuery,
  type ClusterKind,
  type CodeFilter,
  type Criticality,
  type DiscrepancyCode,
  type LapsFilter,
  type Network,
  type Placement,
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
import { ExportButton } from '@/platform/filters/ExportButton'
import { exportHref } from '@/platform/filters/exportHref'
import { FiltersButton, FilterChips, type FilterChip } from '@/platform/filters/FiltersBar'
import { facetValues, useRememberedFacets, type FacetValue } from '@/platform/filters/useRememberedFacets'
import { useFiltersPanel } from '@/platform/filters/useFiltersPanel'
import { ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'
import { findingFacetChips, fromWire, listFrom, statusForFlag, STATUS_OPTIONS, toggleStatus, toggleValue, toWire, valueChips, type FindingFacetFilters } from '@/platform/findings/facets'
import { useFindingSettings } from '@/platform/findings/queries'
import { MANUAL_STATUSES, NEEDS_REASON, STATUSES, STATUS_TITLES, type FindingChange, type FindingStatus } from '@/platform/findings/types'
import { AdCellNote } from '../components/AdCellNote'
import { AssetDrawer } from './AssetDrawer'

const ROW_HEIGHT = 40

const LIST_COLUMNS: ColumnDef[] = [
  { key: 'name', label: 'Имя', width: 240, flex: true },
  { key: 'ip', label: 'IP', width: 128 },
  { key: 'network', label: 'Сеть · группа', width: 176 },
  { key: 'os', label: 'ОС', width: 192 },
  { key: 'sources', label: 'Источники', width: 160 },
  { key: 'seen', label: 'Виден', width: 112 },
  { key: 'discrepancies', label: 'Расхождения', width: 112, align: 'right' },
  { key: 'open', label: 'Открыть', width: 32, resizable: false },
]
// Флажки только у тех, кому можно массово менять: две константы, а не массив в рендере.
const CHECKED_COLUMNS: ColumnDef[] = [{ key: 'check', label: 'Отметка', width: 32, resizable: false, align: 'center' }, ...LIST_COLUMNS]
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

type Filters = Omit<AssetsQuery, 'q' | 'tag' | 'disc_status' | 'assignee' | 'overdue'>
/** Фильтр по статусам расхождений: статусы, исполнитель (`me`, `none`, логин), просроченные. */
type DiscFilters = Omit<FindingFacetFilters, 'risk_expiring'>
type ReturnSelection = { index: number; checked: Set<number>; lastChecked: number | null; scrollKey: string }

function discFromParams(params: URLSearchParams): DiscFilters {
  return { status: listFrom<FindingStatus>(params, 'disc_status', STATUSES), assignee: listFrom(params, 'assignee'), overdue: params.get('overdue') === 'true' || undefined }
}

/** Сети из ссылки: номера (ключ повторяется); не числа отбрасываются. */
function networkIdsFrom(params: URLSearchParams): number[] | undefined {
  const ids = listFrom(params, 'network_id')?.map(Number).filter((n) => Number.isInteger(n) && n > 0)
  return ids?.length ? ids : undefined
}

/** Снапшот из ссылки сводки AD: не число — не передаётся, и сервер ответит 422 на ячейку без снапшота. */
function snapshotFrom(params: URLSearchParams): number | undefined {
  const id = Number(params.get('ad_snapshot'))
  return Number.isInteger(id) && id > 0 ? id : undefined
}

type MultiKey = 'code' | 'source_has' | 'source_missing' | 'criticality' | 'laps' | 'cluster' | 'zone' | 'placement' | 'network_id'

const has = <T extends string | number>(list: readonly T[] | undefined, value: T) => list?.includes(value) ?? false

function isTypingTarget(el: EventTarget | null): boolean {
  return el instanceof HTMLElement && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT' || el.isContentEditable)
}

function day(iso: string | null): string {
  return iso ? new Date(iso).toLocaleDateString('ru-RU') : '—'
}

/**
 * Строка — переключатель значения в мультивыборе. `noCount` — у строки нет счётчика (например, «мои»: сервер его не
 * считает); значение, ушедшее в ноль под другими фильтрами, приглушено, но выбирается.
 */
export function FacetRow({ active, count, onClick, children, noCount }: { active: boolean; count: number | undefined; onClick: () => void; children: ReactNode; noCount?: boolean }) {
  return (
    <button type="button" onClick={onClick} aria-pressed={active} className={cn('flex w-full items-center justify-between gap-2 rounded px-2 py-1.5 text-left text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring', active ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text', !active && !noCount && count === 0 && 'opacity-60')}>
      <span className="min-w-0 flex-1 truncate">{children}</span>
      {!noCount && <span className="font-mono text-[11px] tabular-nums text-text-secondary">{count ?? 0}</span>}
    </button>
  )
}

export function FacetSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="border-b border-grid px-2 py-3">
      <div className="mb-1.5 px-2 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">{title}</div>
      <div className="flex flex-col gap-0.5">{children}</div>
    </div>
  )
}

/** Подпись сети в фильтре: по карточке (тот же кэш, что у useNetwork), пока её нет — номер. */
function networkLabel(id: number, cards: Map<number, Network>): string {
  const n = cards.get(id)
  return n ? `${n.cidr}${n.title ? ` — ${n.title}` : ''}` : `сеть #${id}`
}

/** Добавить сеть в фильтр: сетей тысячи — поиск и первые совпадения, а не весь список. */
function NetworkFacetSearch({ chosen, onPick }: { chosen: number[] | undefined; onPick: (id: number) => void }) {
  const [input, setInput] = useState('')
  const q = useDebouncedValue(input.trim(), 250)
  const found = useNetworkSearch(q)
  const items = (found.data?.items ?? []).filter((n) => !has(chosen, n.id))
  return (
    <div className="flex flex-col gap-0.5">
      <input value={input} onChange={(e) => setInput(e.target.value)} maxLength={200} placeholder={chosen ? 'добавить сеть: адрес, имя, тег…' : 'сеть: адрес, имя, тег, VLAN'} aria-label="Поиск сети" className={INPUT} />
      {q && (
        <ul className="flex max-h-48 flex-col overflow-y-auto">
          {found.isLoading && <li className="px-2 py-1 text-[11px] text-text-secondary">поиск…</li>}
          {!found.isLoading && items.length === 0 && <li className="px-2 py-1 text-[11px] text-text-secondary">не найдено</li>}
          {items.map((n) => (
            <li key={n.id}>
              <button type="button" onClick={() => { onPick(n.id); setInput('') }} className="w-full truncate rounded px-2 py-1 text-left text-xs text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">
                <span className="font-mono">{n.cidr}</span>{n.title ? ` — ${n.title}` : ''}
              </button>
            </li>
          ))}
          {found.data && found.data.total > found.data.items.length && <li className="px-2 py-1 text-[11px] text-text-secondary">первые {NETWORK_PICK_LIMIT} из {found.data.total} — уточните поиск</li>}
        </ul>
      )}
    </div>
  )
}

const INPUT_BASE = 'rounded border border-border bg-app-bg px-2 py-1 text-xs text-text placeholder:text-text-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'
const INPUT = `w-full ${INPUT_BASE}`

function FacetPanel({ facets, zones, networkCards, filters, onToggle, disc, onDisc, total, tag, onTag, adLabel, onClearAd }: {
  facets: AssetsFacets | null
  /** Зоны, которые панель уже показывала (ушедшие в ноль — с 0); считает страница, чтобы память жила, пока панель закрыта. */
  zones: FacetValue[]
  /** Карточки выбранных в фильтре сетей — для подписей. */
  networkCards: Map<number, Network>
  filters: Filters
  onToggle: <K extends keyof Filters>(key: K, value: Filters[K]) => void
  disc: DiscFilters
  onDisc: (next: DiscFilters) => void
  total: number
  tag: string
  onTag: (v: string) => void
  adLabel: string
  onClearAd: () => void
}) {
  const pick = <K extends MultiKey>(key: K, value: NonNullable<Filters[K]>[number]) =>
    onToggle(key, toggleValue(filters[key] as (typeof value)[] | undefined, value) as Filters[K])
  return (
    <div className="flex h-full w-64 shrink-0 flex-col overflow-y-auto border-r border-grid bg-surface">
      <div className="border-b border-grid px-4 py-3 text-xs text-text-secondary">Хостов <span className="font-mono tabular-nums text-text">{total}</span></div>
      <FacetSection title="Расхождения">
        <FacetRow active={has(filters.code, 'any')} count={facets?.code.any} onClick={() => pick('code', 'any')}>{ANY_CODE_LABEL}</FacetRow>
        {CODES.map((c) => (
          <FacetRow key={c} active={has(filters.code, c)} count={facets?.code[c]} onClick={() => pick('code', c)}>{CODE_LABELS[c]}</FacetRow>
        ))}
      </FacetSection>
      {/* Без выбранного статуса считаются и фильтруются расхождения с учитываемым статусом. */}
      <FacetSection title="Статус расхождений">
        {STATUS_OPTIONS.map((o) => (
          <FacetRow key={o.value} active={disc.status?.includes(o.value) ?? false} count={facets?.disc_status[o.value]} onClick={() => onDisc({ ...disc, status: toggleStatus(disc.status, o.value) })}>{o.label}</FacetRow>
        ))}
        <FacetRow active={has(disc.assignee, 'me')} count={undefined} noCount onClick={() => onDisc({ ...disc, assignee: toggleValue(disc.assignee, 'me') })}>мои</FacetRow>
        <FacetRow active={disc.overdue ?? false} count={facets?.disc_overdue} onClick={() => onDisc(disc.overdue ? { ...disc, overdue: undefined } : { ...disc, overdue: true, status: statusForFlag('overdue', disc.status) })}>просроченные</FacetRow>
      </FacetSection>
      <FacetSection title="Источник есть">
        {SOURCES.map((s) => (
          <FacetRow key={s} active={has(filters.source_has, s)} count={facets?.source[s]} onClick={() => pick('source_has', s)}>{SOURCE_LABELS[s]}</FacetRow>
        ))}
      </FacetSection>
      <FacetSection title="Источника нет">
        {SOURCES.map((s) => (
          <FacetRow key={s} active={has(filters.source_missing, s)} count={facets ? total - facets.source[s] : undefined} onClick={() => pick('source_missing', s)}>{SOURCE_LABELS[s]}</FacetRow>
        ))}
      </FacetSection>
      <FacetSection title="Критичность">
        {([...CRITICALITIES, 'none'] as const).map((c) => (
          <FacetRow key={c} active={has(filters.criticality, c)} count={facets?.criticality[c]} onClick={() => pick('criticality', c)}>{CRITICALITY_LABELS[c]}</FacetRow>
        ))}
      </FacetSection>
      {/* Считаются только хосты с наблюдением AD. */}
      <FacetSection title="LAPS">
        {LAPS_VALUES.map((v) => (
          <FacetRow key={v} active={has(filters.laps, v)} count={facets?.laps[v]} onClick={() => pick('laps', v)}>{LAPS_LABELS[v]}</FacetRow>
        ))}
      </FacetSection>
      <FacetSection title="Кластер">
        {CLUSTER_KINDS.map((v) => (
          <FacetRow key={v} active={has(filters.cluster, v)} count={facets?.cluster[v]} onClick={() => pick('cluster', v)}>{CLUSTER_LABELS[v]}</FacetRow>
        ))}
      </FacetSection>
      {/* Расположение — признак группы сети хоста; вне сети или в группе без расположения — «не задано». */}
      <FacetSection title="Расположение">
        {PLACEMENTS.map((p) => (
          <FacetRow key={p} active={has(filters.placement, p)} count={facets?.placement[p]} onClick={() => pick('placement', p)}>{PLACEMENT_LABELS[p]}</FacetRow>
        ))}
      </FacetSection>
      {zones.length > 0 && (
        <FacetSection title="Группа сети">
          {zones.map(({ value: z, count }) => (
            <FacetRow key={z} active={has(filters.zone, z)} count={count} onClick={() => pick('zone', z)}>{z}</FacetRow>
          ))}
        </FacetSection>
      )}
      <FacetSection title="Сеть и тег">
        {/* Сетей тысячи — выбранные показаны строками-переключателями, новая добавляется поиском. */}
        {(filters.network_id ?? []).map((id) => (
          <FacetRow key={id} active count={undefined} noCount onClick={() => pick('network_id', id)}>{networkLabel(id, networkCards)}</FacetRow>
        ))}
        <div className="flex flex-col gap-1.5 px-2">
          <NetworkFacetSearch chosen={filters.network_id} onPick={(id) => pick('network_id', id)} />
          <input value={tag} onChange={(e) => onTag(e.target.value)} placeholder="тег" aria-label="Тег" className={INPUT} />
        </div>
      </FacetSection>
      {/* Ячейка сводки AD приходит ссылкой со страницы «Сводка»; здесь её можно только снять. */}
      {(filters.ad_snapshot !== undefined || filters.ad_cell !== undefined) && (
        <FacetSection title="Сводка AD">
          <FacetRow active count={undefined} noCount onClick={onClearAd}>{adLabel}</FacetRow>
        </FacetSection>
      )}
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
function AssetsTable({ rememberKey, items, selectedIndex, onSelectIndex, onOpen, onReachEnd, checked, onCheck, onCheckAll }: {
  rememberKey: string
  items: AssetItem[]
  selectedIndex: number
  onSelectIndex: (i: number) => void
  onOpen: (i: number) => void
  onReachEnd?: () => void
  checked?: Set<number>
  onCheck: (index: number, range: boolean) => void
  onCheckAll: (on: boolean) => void
}) {
  const { parentRef, rows, totalSize } = useVirtualRows(items.length, ROW_HEIGHT, selectedIndex, onReachEnd, rememberKey)
  const allChecked = checked !== undefined && items.length > 0 && items.every((a) => checked.has(a.id))
  const cols = useColumnWidths('assets-list-columns', checked ? CHECKED_COLUMNS : LIST_COLUMNS)
  return (
    <div ref={parentRef} data-col-resize-root className="h-full overflow-auto">
      <div className="sticky top-0 z-10 grid border-b border-grid bg-surface text-[11px] tracking-wide text-text-secondary uppercase" style={cols.gridStyle}>
        <ResizableHeader cols={cols} as="div" className="px-2 py-2" content={{
          check: <input type="checkbox" className="accent-primary" checked={allChecked} onChange={(e) => onCheckAll(e.target.checked)} aria-label="Отметить все загруженные строки" />,
          open: <span className="sr-only">Открыть</span>,
        }} />
      </div>
      <div style={{ height: totalSize, position: 'relative' }}>
        {rows.map((v) => {
          const a = items[v.index]
          const selected = v.index === selectedIndex
          return (
            <div key={a.id} {...clickableRow(() => { onSelectIndex(v.index); onOpen(v.index) })} className={cn(ROW_FOCUS, 'absolute top-0 left-0 grid w-full cursor-pointer items-center border-b border-grid text-xs', selected ? 'bg-row-selected' : 'hover:bg-row-hover')} style={{ ...cols.gridStyle, height: ROW_HEIGHT, transform: `translateY(${v.start}px)` }}>
              {checked && (
                // Щелчок по флажку не открывает карточку; Shift отмечает диапазон от предыдущего флажка.
                <div className="flex h-full items-center justify-center" onClick={(e) => e.stopPropagation()}>
                  <input type="checkbox" className="accent-primary" checked={checked.has(a.id)} onChange={(e) => onCheck(v.index, (e.nativeEvent as MouseEvent).shiftKey)} aria-label={`Отметить ${a.name || a.fqdn || a.ip || `хост #${a.id}`}`} />
                </div>
              )}
              <div className="min-w-0 truncate px-2">
                <div className="truncate text-text" title={a.name}>
                  {a.name || a.fqdn || a.ip || `хост #${a.id}`}
                  {a.cluster && <span className="ml-1.5 rounded border border-grid px-1 font-mono text-[10px] text-text-secondary" title={a.cluster === 'node' ? 'узел кластера Windows' : 'виртуальное имя кластера Windows, не хост'}>{CLUSTER_LABELS[a.cluster]}</span>}
                </div>
                <div className="truncate text-[10px] text-text-secondary" title={a.fqdn}>{a.fqdn}</div>
              </div>
              <div className="min-w-0 truncate px-2 font-mono text-text-secondary">{a.ip || '—'}</div>
              <div className="min-w-0 truncate px-2 text-text-secondary" title={a.network?.title}>{a.network ? `${a.network.cidr}${a.network.zone ? ` · ${a.network.zone}` : ''}` : '—'}</div>
              <div className="min-w-0 truncate px-2 text-text-secondary" title={a.os}>{a.os || '—'}</div>
              <div className="min-w-0 overflow-hidden px-2"><SourceBadges item={a} /></div>
              <div className="min-w-0 truncate px-2 text-text-secondary">{day(a.last_seen)}</div>
              <div className={cn('min-w-0 truncate px-2 text-right font-mono tabular-nums', a.discrepancy_count > 0 ? 'text-risk-high' : 'text-text-secondary')} title={a.codes.map((c) => CODE_LABELS[c]).join(', ')}>
                {a.discrepancy_count}
              </div>
              <div className="flex justify-end pr-2"><ChevronRight size={14} className="shrink-0 text-text-secondary/40" aria-hidden /></div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

const split = (text: string) => text.split(',').map((t) => t.trim()).filter(Boolean)

/**
 * Статус расхождения одного кода у отмеченных хостов — статусы находок платформы. Коды — те, что есть
 * в текущем списке (фасет); обоснование обязательно для «Принят риск» и «Ложное срабатывание».
 */
function DiscrepancyBulkForm({ ids, facets, code: filterCode }: { ids: number[]; facets: AssetsFacets | null; code: CodeFilter | undefined }) {
  const bulk = useDiscrepancyBulk()
  const settings = useFindingSettings()
  const { admin } = useCan()
  const present = CODES.filter((c) => (facets?.code[c] ?? 0) > 0)
  const [code, setCode] = useState<DiscrepancyCode | ''>(filterCode && filterCode !== 'any' ? filterCode : '')
  const [status, setStatus] = useState<FindingStatus | ''>('')
  const [riskUntil, setRiskUntil] = useState('')
  const [comment, setComment] = useState('')
  const canAcceptRisk = admin || settings.data?.risk_accept_role !== 'admin'
  const choices = MANUAL_STATUSES.filter((s) => s !== 'risk_accepted' || canAcceptRisk)
  const needsReason = status !== '' && NEEDS_REASON.includes(status)
  const blocked = !code || !status || (needsReason && !comment.trim())
  function apply() {
    if (!code || !status) return
    const change: FindingChange = { status }
    if (status === 'risk_accepted' && riskUntil) change.risk_until = riskUntil
    if (comment.trim()) change.comment = comment.trim()
    bulk.mutate({ ids, code, change }, { onSuccess: () => { setStatus(''); setRiskUntil(''); setComment('') } })
  }
  return (
    <div className="flex basis-full flex-wrap items-center gap-2">
      <span className="text-text-secondary">Расхождение:</span>
      <select value={code} onChange={(e) => setCode(e.target.value as DiscrepancyCode | '')} aria-label="Код расхождения" className={cn(INPUT_BASE, 'w-52')}>
        <option value="">— код —</option>
        {(code && !present.includes(code) ? [code, ...present] : present).map((c) => <option key={c} value={c}>{CODE_LABELS[c]}</option>)}
      </select>
      <span className="text-text-secondary">→</span>
      <select value={status} onChange={(e) => setStatus(e.target.value as FindingStatus | '')} aria-label="Статус расхождения" className={cn(INPUT_BASE, 'w-44')}>
        <option value="">— статус —</option>
        {choices.map((s) => <option key={s} value={s}>{STATUS_TITLES[s]}</option>)}
      </select>
      {status === 'risk_accepted' && <input type="date" value={riskUntil} onChange={(e) => setRiskUntil(e.target.value)} aria-label="Риск принят до" title="Риск принят до" className={INPUT_BASE} />}
      <input value={comment} onChange={(e) => setComment(e.target.value)} placeholder={needsReason ? 'обоснование (обязательно)' : 'комментарий'} aria-label="Комментарий к статусу" className={cn(INPUT_BASE, 'w-64')} />
      <Button variant="primary" disabled={blocked} loading={bulk.isPending} onClick={apply}>Применить статус</Button>
      {bulk.error && <span className="text-kind-1">{bulk.error.message}</span>}
      {bulk.isSuccess && !bulk.isPending && <span className="text-text-secondary">изменено расхождений: {bulk.data.changed}</span>}
    </div>
  )
}

/** Удаление отмеченных: подтверждение с числом; хост, которого источник ещё видит, вернётся при синхронизации. */
function BulkDelete({ ids, onDone }: { ids: number[]; onDone: () => void }) {
  const remove = useBulkDelete()
  const [confirm, setConfirm] = useState(false)
  return (
    <>
      <Button variant="ghost" onClick={() => setConfirm(true)} className="text-risk-high"><Trash2 size={13} aria-hidden /> Удалить</Button>
      {remove.error && <span className="text-kind-1">{remove.error.message}</span>}
      {confirm && (
        <div role="dialog" aria-label="Удалить хосты" className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="w-full max-w-md rounded border border-grid bg-surface p-4">
            <div className="mb-2 text-sm font-semibold text-text">Удалить хостов: {ids.length}?</div>
            <p className="mb-4 text-xs text-text-secondary">Хосты исчезнут вместе с наблюдениями источников. Те, кого источник всё ещё видит, вернутся при следующей синхронизации — удаление чистит реестр, а не прячет хост.</p>
            <div className="flex justify-end gap-2">
              <Button onClick={() => setConfirm(false)}>Отмена</Button>
              <Button variant="danger" loading={remove.isPending} onClick={() => remove.mutate(ids, { onSuccess: () => { setConfirm(false); onDone() } })}>Удалить</Button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}

/** Массовое изменение отмеченных хостов: критичность и теги (добавить, снять), статус расхождения, удаление. Заметка и сеть — только в карточке. */
function BulkBar({ ids, total, selectingAll, onSelectAll, onClear, facets, code }: {
  ids: number[]; total: number; selectingAll: boolean; onSelectAll: () => void; onClear: () => void; facets: AssetsFacets | null; code: CodeFilter | undefined
}) {
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
      <BulkDelete ids={ids} onDone={onClear} />
      {bulk.error && <span className="text-kind-1">{bulk.error.message}</span>}
      {bulk.isSuccess && !bulk.isPending && <span className="text-text-secondary">изменено хостов: {bulk.data.updated}</span>}
      <DiscrepancyBulkForm key={code ?? ''} ids={ids} facets={facets} code={code} />
    </div>
  )
}

/**
 * Реестр хостов: таблица с фасетами слева, карточка справа. Адрес задаёт начальные фильтры — сюда ведут
 * ссылки обзора; `?asset=<id>` сразу открывает карточку — так ведут ссылки «в Assets» из антивируса и VM.
 */
export function AssetsPage() {
  const params = useSearchParams()
  const { navigate } = useRouter()
  const client = useQueryClient()
  const [returnSelection] = useState(() => readViewState<ReturnSelection>(client, window.history.state?.assetContainersReturn))
  const [filters, setFilters] = useListState<Filters>('assets-list:filters', () => ({
    source_has: listFrom<AssetSource>(params, 'source_has', SOURCES),
    source_missing: listFrom<AssetSource>(params, 'source_missing', SOURCES),
    code: listFrom<CodeFilter>(params, 'code', ['any', ...CODES]),
    zone: fromWire(listFrom(params, 'zone')),
    placement: fromWire(listFrom(params, 'placement'))?.filter((p) => (PLACEMENTS as string[]).includes(p)) as Placement[] | undefined,
    criticality: listFrom<Criticality | 'none'>(params, 'criticality', [...CRITICALITIES, 'none']),
    laps: listFrom<LapsFilter>(params, 'laps', LAPS_VALUES),
    cluster: listFrom<ClusterKind>(params, 'cluster', CLUSTER_KINDS),
    network_id: networkIdsFrom(params),
    ad_snapshot: snapshotFrom(params),
    ad_cell: params.get('ad_cell') ?? undefined,
  }), params.size === 0)
  const [disc, setDisc] = useListState<DiscFilters>('assets-list:disc', () => discFromParams(params), params.size === 0)
  const [searchInput, setSearchInput] = useListState('assets-list:searchInput', params.get('q') ?? '', params.size === 0)
  const [tagInput, setTagInput] = useListState('assets-list:tagInput', params.get('tag') ?? '', params.size === 0)
  const q = useDebouncedValue(searchInput, 250)
  const tag = useDebouncedValue(tagInput, 250)
  const [selectedIndex, setSelectedIndex] = useListState('assets-list:selectedIndex', returnSelection?.index ?? 0, params.size === 0)
  const [openId, setOpenId] = useState<number | null>(() => (Number(params.get('asset')) > 0 ? Number(params.get('asset')) : null))
  const searchRef = useRef<HTMLInputElement>(null)
  const { write } = useCan()
  const filtersPanel = useFiltersPanel(FILTERS_PAGE)
  const [checked, setChecked] = useState<Set<number>>(() => returnSelection?.checked ?? new Set())
  const lastChecked = useRef<number | null>(returnSelection?.lastChecked ?? null)
  const allIds = useAssetIds()

  const queryArgs = useMemo<AssetsQuery>(
    () => ({
      ...filters, zone: toWire(filters.zone), placement: toWire(filters.placement), q: q || undefined, tag: tag.trim() || undefined,
      disc_status: disc.status, assignee: disc.assignee, overdue: disc.overdue || undefined,
    }),
    [filters, q, tag, disc],
  )
  const query = useAssets(queryArgs)
  const items = useMemo(() => query.data?.pages.flatMap((p) => p.items) ?? [], [query.data])
  const first = query.data?.pages[0]
  const total = first?.total ?? 0
  // Зоны считаются по отфильтрованному набору: ушедшие в ноль страница помнит (не панель — та по умолчанию закрыта
  // и при закрытии забывала бы), иначе вторую зону не выбрать.
  const zones = useRememberedFacets(first?.facets ? { zone: facetValues(first.facets.zone) } : undefined).zone ?? []
  // Новый фильтр — другой список: курсор в начало, отметки сняты.
  const previousQuery = useRef(queryArgs)
  const initialQuery = useRef(queryArgs)
  const scrollKey = returnSelection && queryArgs === initialQuery.current ? returnSelection.scrollKey : `assets:${JSON.stringify(queryArgs)}`
  function rememberForContainers(id: number) {
    const key = `assets:containers-return:${crypto.getRandomValues(new Uint32Array(2)).join('-')}`
    const owner = viewOwner(client)
    writeViewState(client, key, owner, { index: selectedIndex, checked, lastChecked: lastChecked.current, scrollKey: key })
    writeViewState(client, `scroll:${key}`, owner, readViewState<number>(client, `scroll:${scrollKey}`) ?? 0)
    const url = '/assets/list' + buildQuery({ ...queryArgs, q: searchInput, tag: tagInput, asset: id })
    window.history.replaceState({ ...window.history.state, assetContainersReturn: key }, '', url)
  }
  useEffect(() => {
    if (previousQuery.current === queryArgs) return
    previousQuery.current = queryArgs
    setSelectedIndex(0); setChecked(new Set()); lastChecked.current = null
  }, [queryArgs])
  const selected: AssetItem | null = items[selectedIndex] ?? null
  const networkCards = useNetworkCards(filters.network_id ?? [])

  function toggle<K extends keyof Filters>(key: K, value: Filters[K]) { setFilters((prev) => ({ ...prev, [key]: value })) }
  // Страница не пишет фильтры в адрес: ячейка снимается и из адреса, иначе вернётся после перезагрузки.
  function dropAdFromUrl() {
    if (!params.has('ad_snapshot') && !params.has('ad_cell')) return
    const rest = new URLSearchParams(params)
    rest.delete('ad_snapshot')
    rest.delete('ad_cell')
    navigate(`/assets/list${rest.size ? `?${rest}` : ''}`, { replace: true })
  }
  function clearAd() { setFilters((prev) => ({ ...prev, ad_snapshot: undefined, ad_cell: undefined })); dropAdFromUrl() }
  function clearAll() { setFilters({}); setDisc({}); setSearchInput(''); setTagInput(''); dropAdFromUrl() }
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
  // Чип на каждое выбранное значение: крестик снимает только его.
  // Чип и при половине пары из адреса: сервер ответит 422, и снять её должно быть чем.
  const adOn = filters.ad_snapshot !== undefined || filters.ad_cell !== undefined
  const adCheck = adOn ? first?.ad_cell : undefined
  const adLabel = adCheck ? `Сводка AD: ${adCheck.label}` : 'Сводка AD'
  const chips: FilterChip[] = [
    ...(adOn ? [{ label: adLabel, clear: clearAd }] : []),
    ...valueChips('Расхождения', filters.code, (c) => (c === 'any' ? ANY_CODE_LABEL : CODE_LABELS[c]), (v) => toggle('code', v)),
    ...valueChips('Источник есть', filters.source_has, (s) => SOURCE_LABELS[s], (v) => toggle('source_has', v)),
    ...valueChips('Источника нет', filters.source_missing, (s) => SOURCE_LABELS[s], (v) => toggle('source_missing', v)),
    ...valueChips('Критичность', filters.criticality, (c) => CRITICALITY_LABELS[c], (v) => toggle('criticality', v)),
    ...valueChips('LAPS', filters.laps, (v) => LAPS_LABELS[v], (v) => toggle('laps', v)),
    ...valueChips('Кластер', filters.cluster, (v) => CLUSTER_LABELS[v], (v) => toggle('cluster', v)),
    ...valueChips('Расположение', filters.placement, (p) => PLACEMENT_LABELS[p as Placement] ?? p, (v) => toggle('placement', v)),
    ...valueChips('Группа сети', filters.zone, (z) => z || 'без группы', (v) => toggle('zone', v)),
    ...valueChips('Сеть', filters.network_id, (id) => networkLabel(id, networkCards), (v) => toggle('network_id', v)),
  ]
  if (tagInput.trim()) chips.push({ label: `тег ${tagInput.trim()}`, clear: () => setTagInput('') })
  chips.push(...findingFacetChips(disc, setDisc).map((c) => ({ ...c, label: `расхождения · ${c.label.toLowerCase()}` })))
  // Ссылка на открытую карточку остаётся в истории до её закрытия или смены.
  useEffect(() => {
    if (!params.has('asset') || Number(params.get('asset')) === openId) return
    const rest = new URLSearchParams(params)
    rest.delete('asset')
    navigate(`/assets/list${rest.size ? `?${rest}` : ''}`, { replace: true })
  }, [params, navigate, openId])

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

  const hasFilters = Object.values(filters).some((v) => v !== undefined) || Object.values(disc).some((v) => v !== undefined) || q !== '' || tag !== ''
  const errorMessage = query.error instanceof ApiRequestError
    ? (adOn && query.error.status === 422 ? 'Ссылка из сводки AD неполная — откройте её со страницы сводки заново.'
      : adOn && (query.error.status === 404 || query.error.status === 409) ? `Ячейка сводки AD не открывается: ${query.error.message}` : query.error.message)
    : query.isError ? 'Не удалось загрузить хосты' : null

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex shrink-0 flex-wrap items-center gap-3 border-b border-grid bg-surface px-4 py-2.5">
        <h1 className="text-sm font-semibold text-text">Хосты</h1>
        <FiltersButton open={filtersPanel.open} onToggle={filtersPanel.toggle} count={chips.length} />
        <ExportButton href={exportHref('/api/assets/assets/export', queryArgs)} total={first?.total} disabled={query.isLoading} />
        <div className="relative max-w-sm flex-1">
          <Search size={14} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-text-secondary" aria-hidden />
          <input ref={searchRef} value={searchInput} onChange={(e) => setSearchInput(e.target.value)} placeholder="Имя, FQDN, IP, ОС… (/)" className="w-full rounded border border-border bg-app-bg py-1.5 pr-3 pl-8 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" />
        </div>
        {hasFilters && <button type="button" onClick={clearAll} className="flex items-center gap-1.5 rounded px-2 py-1 text-xs text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"><FilterX size={13} aria-hidden /> Сбросить</button>}
        <div className="font-mono text-xs tabular-nums text-text-secondary">{query.data ? (items.length < total ? `${items.length} из ${total}` : total) : '…'}</div>
        {!filtersPanel.open && <FilterChips chips={chips} />}
        {adCheck && filters.ad_snapshot !== undefined && filters.ad_cell !== undefined && <AdCellNote check={adCheck} snapshot={filters.ad_snapshot} cell={filters.ad_cell} page="assets" />}
      </header>
      <div className="flex min-h-0 flex-1">
        {filtersPanel.open && <FacetPanel facets={first?.facets ?? null} zones={zones} networkCards={networkCards} filters={filters} onToggle={toggle} disc={disc} onDisc={setDisc} total={total} tag={tagInput} onTag={setTagInput} adLabel={adLabel} onClearAd={clearAd} />}
        <div className="flex min-w-0 flex-1 flex-col bg-app-bg">
          {write && checked.size > 0 && (
            <BulkBar ids={[...checked]} total={total} selectingAll={allIds.isPending} onClear={() => checkAll(false)} facets={first?.facets ?? null} code={filters.code?.length === 1 ? filters.code[0] : undefined}
              onSelectAll={() => allIds.mutate(queryArgs, { onSuccess: (r) => setChecked(new Set(r.ids)) })} />
          )}
          <div className="min-h-0 flex-1">
            {query.isLoading && <FullPageSpinner />}
            {errorMessage && <div className="p-6"><ErrorState message={errorMessage} onRetry={() => query.refetch()} /></div>}
            {!query.isLoading && !errorMessage && items.length === 0 && (
              <div className="p-6">
                <EmptyState
                  icon={FilterX}
                  title={hasFilters ? 'Ничего не найдено' : 'Хостов ещё нет'}
                  description={hasFilters ? 'Ни один хост не подходит под фильтры.' : 'Хосты появятся после импорта в модулях VM, антивируса или AD — или после синхронизации кнопкой на обзоре и в настройках.'}
                />
              </div>
            )}
            {!query.isLoading && !errorMessage && items.length > 0 && (
              <AssetsTable rememberKey={scrollKey} items={items} selectedIndex={selectedIndex} onSelectIndex={setSelectedIndex} onOpen={(i) => setOpenId(items[i].id)} onReachEnd={() => { if (query.hasNextPage && !query.isFetchingNextPage) query.fetchNextPage() }}
                checked={write ? checked : undefined} onCheck={check} onCheckAll={checkAll} />
            )}
          </div>
        </div>
      </div>
      <AssetDrawer assetId={openId} onClose={() => setOpenId(null)} onOpenAsset={setOpenId} beforeContainers={rememberForContainers} />
    </div>
  )
}
