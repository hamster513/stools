import { useEffect, useMemo, useRef, useState } from 'react'
import { clickableRow, ROW_FOCUS } from '@/components/ui/clickableRow'
import { ChevronRight, FilterX, Monitor, Search, X } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useHostDetail, useHosts, usePolicy, useServers } from '@/modules/ksc/api/queries'
import {
  AGENT_LABELS,
  BASES_LABELS,
  IN_AD_LABELS,
  PROTECTION_LABELS,
  RTP_STATE_LABELS,
  type ComponentState,
  type Host,
  type HostAgent,
  type HostBases,
  type HostProtection,
  type HostsQuery,
  type HostsResponse,
} from '@/modules/ksc/api/types'
import { ExportButton } from '@/platform/filters/ExportButton'
import { exportHref } from '@/platform/filters/exportHref'
import { FiltersButton, FilterChips, type FilterChip } from '@/platform/filters/FiltersBar'
import { facetValues, useRememberedFacets, type FacetValue } from '@/platform/filters/useRememberedFacets'
import { listFrom, toggleValue, valueChips } from '@/platform/findings/facets'
import { useFiltersPanel } from '@/platform/filters/useFiltersPanel'
import { ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { useVirtualRows } from '@/hooks/useVirtualRows'
import { useSearchParams, Link } from '@/lib/router'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner, Spinner } from '@/components/ui/Spinner'
import { cn } from '@/lib/cn'
import { FacetRow, FacetSection } from './policies/Facets'
import type { TabDef } from './policies/TabBar'
import { ExclusionsTable } from './ExclusionsPage'
import { NetRulesTable } from './NetRulesPage'
import { DrawerTabs } from './hosts/DrawerTabs'
import { HostFindings, HostOverview } from './hosts/HostOverview'
import { HostPoliciesTab } from './hosts/HostPoliciesTab'
import { HostTagsTab } from './hosts/HostTagsTab'

const ROW_HEIGHT = 40

type HostFilters = Pick<HostsQuery, 'group' | 'product' | 'agent' | 'protection' | 'bases' | 'in_ad' | 'status' | 'status_reason' | 'component' | 'component_state' | 'tag' | 'policy'>

const COMPONENT_STATES: { key: ComponentState; label: string }[] = [
  { key: 'on', label: 'работает' },
  { key: 'off', label: 'не работает' },
  { key: 'other', label: 'прочее' },
  { key: 'none', label: 'нет компонента' },
]
const COMPONENT_STATE_LABELS = Object.fromEntries(COMPONENT_STATES.map((c) => [c.key, c.label])) as Record<ComponentState, string>
const KSC_STATUS_LABELS: Record<string, string> = { ok: 'ок', warning: 'предупреждение', critical: 'критично' }
const REASONS_NOT_PARSED = 'причины не разобраны — пересчитайте снапшот'

type MultiKey = 'group' | 'product' | 'agent' | 'protection' | 'bases' | 'in_ad' | 'status' | 'status_reason' | 'tag'

const has = (list: readonly string[] | undefined, value: string) => list?.includes(value) ?? false

const HOST: ColumnDef = { key: 'host', label: 'Хост', width: 224, flex: true }
const GROUP: ColumnDef = { key: 'group', label: 'Группа', width: 160 }
const TAGS: ColumnDef = { key: 'tags', label: 'Теги', width: 192 }
const REST: ColumnDef[] = [
  { key: 'os', label: 'ОС', width: 160 },
  { key: 'agent', label: 'Агент', width: 128 },
  { key: 'protection', label: 'Защита', width: 160 },
  { key: 'bases', label: 'Базы', width: 128 },
  { key: 'fullscan', label: 'Полный поиск', width: 112 },
  { key: 'threats', label: 'Угрозы', width: 64, align: 'right' },
  { key: 'status', label: 'Статус KSC', width: 144 },
  { key: 'in_ad', label: 'AD', width: 96 },
  { key: 'findings', label: 'Находок', width: 80, align: 'right' },
  // Стрелка в конце строки: 14 px и отступ 8 px.
  { key: 'open', label: '', width: 22, resizable: false },
]
// Колонка «Теги» есть, только если теги собирались; ширины обоих вариантов хранятся под одним ключом.
const COLUMNS = [HOST, GROUP, ...REST]
const COLUMNS_WITH_TAGS = [HOST, GROUP, TAGS, ...REST]
const TAGS_SHOWN = 3

function isTypingTarget(el: EventTarget | null): boolean {
  return el instanceof HTMLElement && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable)
}

type HostRemembered = Partial<Record<'group' | 'product' | 'in_ad' | 'status_reason' | 'tag' | 'component', FacetValue[]>>

/** Значения перечислимых фасетов ответа для useRememberedFacets; у компонента число — хостов, где он не работает. */
function hostFacetValues(facets: NonNullable<HostsResponse['facets']>) {
  const componentFacet = facets.component ?? {}
  return {
    group: facetValues(facets.group),
    product: facetValues(facets.product),
    in_ad: facetValues(facets.in_ad),
    status_reason: facetValues(facets.status_reason),
    tag: Object.entries(facets.tag ?? {}).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0], 'ru')).map(([value, count]) => ({ value, count })),
    component: Object.keys(componentFacet).sort((a, b) => (componentFacet[b]?.off ?? 0) - (componentFacet[a]?.off ?? 0) || a.localeCompare(b, 'ru'))
      .map((value) => ({ value, count: componentFacet[value]?.off ?? 0 })),
  }
}

function HostFacetPanel({ facets, remembered, filters, onToggle, onComponent, tagsCollected, total }: {
  facets: HostsResponse['facets']
  /** Значения, которые панель уже показывала; считает страница, чтобы память жила, пока панель закрыта. */
  remembered: HostRemembered
  filters: HostFilters
  onToggle: <K extends keyof HostFilters>(key: K, value: HostFilters[K]) => void
  onComponent: (names: string[] | undefined) => void
  tagsCollected: boolean
  total: number
}) {
  // Счётчики считаются по отфильтрованному набору: значения, ушедшие в ноль, панель помнит — иначе второе не выбрать.
  // Компонент остаётся в списке, даже если под «нет компонента» его не осталось ни у одного хоста.
  const componentFacet = facets?.component ?? {}
  const groups = remembered.group ?? []
  const products = remembered.product ?? []
  const inAd = remembered.in_ad ?? []
  const statusReasons = remembered.status_reason ?? []
  const tags = remembered.tag ?? []
  const components = (remembered.component ?? []).map((c) => c.value)
  for (const c of filters.component ?? []) if (!components.includes(c)) components.push(c)
  const pick = <K extends MultiKey>(key: K, value: string) => onToggle(key, toggleValue(filters[key] as string[] | undefined, value) as HostFilters[K])
  return (
    <div className="flex h-full w-64 shrink-0 flex-col overflow-y-auto border-r border-grid bg-surface">
      <div className="border-b border-grid px-4 py-3 text-xs text-text-secondary">Хостов <span className="font-mono tabular-nums text-text">{total}</span></div>
      <FacetSection title="Защита">
        {(Object.keys(PROTECTION_LABELS) as HostProtection[]).map((p) => (
          <FacetRow key={p} active={has(filters.protection, p)} count={facets?.protection[p] ?? 0} onClick={() => pick('protection', p)}>{PROTECTION_LABELS[p]}</FacetRow>
        ))}
      </FacetSection>
      <FacetSection title="Агент">
        {(Object.keys(AGENT_LABELS) as HostAgent[]).map((a) => (
          <FacetRow key={a} active={has(filters.agent, a)} count={facets?.agent[a] ?? 0} onClick={() => pick('agent', a)}>{AGENT_LABELS[a]}</FacetRow>
        ))}
      </FacetSection>
      <FacetSection title="Базы">
        {(Object.keys(BASES_LABELS) as HostBases[]).map((b) => (
          <FacetRow key={b} active={has(filters.bases, b)} count={facets?.bases[b] ?? 0} onClick={() => pick('bases', b)}>{BASES_LABELS[b]}</FacetRow>
        ))}
      </FacetSection>
      {inAd.length > 0 && (
        <FacetSection title="AD">
          {inAd.map(({ value: k, count }) => (
            <FacetRow key={k} active={has(filters.in_ad, k)} count={count} onClick={() => pick('in_ad', k)}>{IN_AD_LABELS[k] ?? k}</FacetRow>
          ))}
        </FacetSection>
      )}
      <FacetSection title="Статус KSC">
        {(['ok', 'warning', 'critical'] as const).map((s) => (
          <FacetRow key={s} active={has(filters.status, s)} count={facets?.status[s] ?? 0} onClick={() => pick('status', s)}>{KSC_STATUS_LABELS[s]}</FacetRow>
        ))}
      </FacetSection>
      {statusReasons.length > 0 && (
        <FacetSection title="Причина статуса">
          {statusReasons.map(({ value: r, count }) => (
            <FacetRow key={r} active={has(filters.status_reason, r)} count={count} onClick={() => pick('status_reason', r)}>{r}</FacetRow>
          ))}
        </FacetSection>
      )}
      <FacetSection title="Компонент защиты">
        <div className="mb-1 px-2 text-[10px] text-text-secondary">число — хостов, где компонент не работает</div>
        {components.map((name) => (
          <div key={name}>
            <FacetRow active={has(filters.component, name)} count={componentFacet[name]?.off ?? 0} onClick={() => onComponent(toggleValue(filters.component, name))}>{name}</FacetRow>
            {/* Состояние одно на все выбранные компоненты; число у состояния — по этому компоненту. */}
            {has(filters.component, name) && (
              <div className="mt-0.5 mb-1 ml-3 flex flex-col gap-0.5 border-l border-grid pl-1">
                {COMPONENT_STATES.map(({ key, label }) => (
                  <FacetRow key={key} active={filters.component_state === key} count={key === 'none' ? '—' : componentFacet[name]?.[key] ?? 0} onClick={() => onToggle('component_state', filters.component_state === key ? undefined : key)}>{label}</FacetRow>
                ))}
              </div>
            )}
          </div>
        ))}
      </FacetSection>
      {tagsCollected && facets?.tag && (
        <FacetSection title="Тег">
          <FacetRow active={has(filters.tag, '-')} onClick={() => pick('tag', '-')}>без тегов</FacetRow>
          {tags.map(({ value: t, count }) => (
            <FacetRow key={t} active={has(filters.tag, t)} count={count} onClick={() => pick('tag', t)}>{t}</FacetRow>
          ))}
        </FacetSection>
      )}
      <FacetSection title="Группа">
        {groups.map(({ value: g, count }) => (
          <FacetRow key={g} active={has(filters.group, g)} count={count} onClick={() => pick('group', g)}>{g}</FacetRow>
        ))}
      </FacetSection>
      <FacetSection title="Продукт">
        {products.map(({ value: p, count }) => (
          <FacetRow key={p} active={has(filters.product, p)} count={count} onClick={() => pick('product', p)}>{p}</FacetRow>
        ))}
      </FacetSection>
    </div>
  )
}

function TagChips({ tags }: { tags: string[] }) {
  if (tags.length === 0) return <span className="text-text-secondary">—</span>
  return (
    <div className="flex items-center gap-1 overflow-hidden" title={tags.join(', ')}>
      {tags.slice(0, TAGS_SHOWN).map((t) => <span key={t} className="max-w-[64px] truncate rounded bg-row-hover px-1.5 py-0.5 text-[10px] text-text">{t}</span>)}
      {tags.length > TAGS_SHOWN && <span className="shrink-0 text-[10px] text-text-secondary">+{tags.length - TAGS_SHOWN}</span>}
    </div>
  )
}

/** Ячейка статуса KSC: слово статуса и число причин; сами причины — в подсказке. */
function StatusCell({ host: h }: { host: Host }) {
  const reasons = h.status_reasons
  const title = reasons === null ? REASONS_NOT_PARSED : reasons.join('\n')
  return (
    <div className={cn('min-w-0 truncate px-2', h.status === 'critical' ? 'text-risk-high' : h.status === 'warning' ? 'text-risk-medium' : 'text-text-secondary')} title={title}>
      {KSC_STATUS_LABELS[h.status]}{reasons && reasons.length > 0 ? ` · ${reasons.length}` : ''}
    </div>
  )
}

function HostsTable({ items, selectedIndex, onSelectIndex, onOpen, onReachEnd, serverId, tagsCollected }: { items: Host[]; selectedIndex: number; onSelectIndex: (i: number) => void; onOpen: (i: number) => void; onReachEnd?: () => void; serverId: number; tagsCollected: boolean }) {
  const { parentRef, rows, totalSize } = useVirtualRows(items.length, ROW_HEIGHT, selectedIndex, onReachEnd)
  const cols = useColumnWidths('ksc-hosts-columns', tagsCollected ? COLUMNS_WITH_TAGS : COLUMNS)

  return (
    <div ref={parentRef} data-col-resize-root className="h-full overflow-auto">
      <div style={cols.gridStyle} className="sticky top-0 z-10 grid border-b border-grid bg-surface text-[11px] tracking-wide text-text-secondary uppercase">
        <ResizableHeader cols={cols} as="div" className="px-2 py-2" />
      </div>
      <div style={{ height: totalSize, position: 'relative' }}>
        {rows.map((v) => {
          const h = items[v.index]
          const selected = v.index === selectedIndex
          return (
            <div key={h.id} {...clickableRow(() => { onSelectIndex(v.index); onOpen(v.index) })} className={cn(ROW_FOCUS, 'absolute top-0 left-0 grid w-full cursor-pointer items-center border-b border-grid text-xs', selected ? 'bg-row-selected' : 'hover:bg-row-hover')} style={{ ...cols.gridStyle, height: ROW_HEIGHT, transform: `translateY(${v.start}px)` }}>
              <div className="min-w-0 truncate px-2">
                <div className="truncate text-text" title={h.name}>{h.name}</div>
                <div className="truncate text-[10px] text-text-secondary" title={h.fqdn}>{h.fqdn}</div>
              </div>
              <div className="min-w-0 truncate px-2 text-text-secondary" title={h.group}>{h.group}</div>
              {tagsCollected && <div className="min-w-0 px-2"><TagChips tags={h.tags ?? []} /></div>}
              <div className="min-w-0 truncate px-2 text-text-secondary" title={h.os}>{h.os}</div>
              <div className="min-w-0 truncate px-2 text-text-secondary">{AGENT_LABELS[h.agent]}{h.agent_version ? ` · ${h.agent_version}` : ''}</div>
              <div className={cn('min-w-0 truncate px-2', h.protection === 'off' ? 'text-risk-high' : 'text-text-secondary')}>
                {PROTECTION_LABELS[h.protection]}{h.protection === 'off' ? ` · ${RTP_STATE_LABELS[h.rtp_state] ?? h.rtp_state}` : ''}
              </div>
              <div className={cn('min-w-0 truncate px-2', h.bases === 'old' && 'text-risk-high')}>{h.bases_at ? new Date(h.bases_at).toLocaleDateString('ru-RU') : '—'} · {BASES_LABELS[h.bases]}</div>
              <div className="min-w-0 truncate px-2 text-text-secondary">{h.last_fullscan_at ? new Date(h.last_fullscan_at).toLocaleDateString('ru-RU') : 'никогда'}</div>
              <div className={cn('min-w-0 px-2 text-right font-mono tabular-nums', h.threats > 0 && 'text-risk-high')}>{h.threats}</div>
              <StatusCell host={h} />
              <div className="min-w-0 truncate px-2 text-text-secondary">{h.in_ad ? IN_AD_LABELS[h.in_ad] : '—'}</div>
              <div role="presentation" className="min-w-0 px-2 text-right" onClick={(e) => e.stopPropagation()} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') e.stopPropagation() }}>
                {h.findings > 0 ? (
                  <Link to={`/ksc/servers/${serverId}/findings?q=${encodeURIComponent(h.name)}`} className="font-mono tabular-nums text-text hover:text-primary">{h.findings}</Link>
                ) : (
                  <span className="font-mono tabular-nums text-text-secondary">0</span>
                )}
              </div>
              <div className="flex justify-end pr-2"><ChevronRight size={14} className="shrink-0 text-text-secondary/40" aria-hidden /></div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

const DRAWER_TABS: TabDef[] = [
  { key: 'overview', label: 'Обзор' },
  { key: 'policies', label: 'Политики и профили' },
  { key: 'tags', label: 'Теги' },
  { key: 'exclusions', label: 'Исключения' },
  { key: 'netrules', label: 'Сетевые правила' },
  { key: 'findings', label: 'Находки' },
]

/**
 * Содержимое панели хоста: шапка, вкладки (состояние здесь, не в адресе) и раздел. `key` по хосту возвращает «Обзор» и фокус
 * на кнопку закрытия. Таблицы исключений и правил занимают панель целиком и прокручиваются сами; панель записи из них
 * открывается поверх (порталом, `z-50`).
 */
function HostDrawerBody({ hostId, snapshotId, serverId, onClose }: { hostId: string; snapshotId: number; serverId: number; onClose: () => void }) {
  const detail = useHostDetail(snapshotId, hostId)
  const [tab, setTab] = useState('overview')
  const closeRef = useRef<HTMLButtonElement>(null)
  useEffect(() => { closeRef.current?.focus() }, [])
  const h = detail.data
  const errorMessage = detail.error instanceof ApiRequestError ? detail.error.message : detail.isError ? 'Не удалось загрузить хост' : null
  const table = tab === 'exclusions' || tab === 'netrules'

  return (
    <>
      <div className="flex items-center justify-between border-b border-grid px-4 py-3">
        <div className="flex min-w-0 items-center gap-2">
          <Monitor size={16} className="shrink-0 text-text-secondary" aria-hidden />
          <span className="truncate text-sm text-text">{h?.name ?? hostId}</span>
          {h && <span className="truncate text-xs text-text-secondary" title={h.group}>{h.group}</span>}
        </div>
        <button ref={closeRef} type="button" onClick={onClose} className="rounded p-1 text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" aria-label="Свернуть (Esc)"><X size={16} aria-hidden /></button>
      </div>
      <DrawerTabs tabs={DRAWER_TABS} current={tab} onSelect={setTab} label="Разделы хоста" />
      {table ? (
        <div className="min-h-0 flex-1">
          {tab === 'exclusions' && <ExclusionsTable snapshotId={snapshotId} serverId={serverId} hostId={hostId} policyIds={h?.policies.map((p) => p.id)} />}
          {tab === 'netrules' && <NetRulesTable snapshotId={snapshotId} serverId={serverId} hostId={hostId} policyIds={h?.policies.map((p) => p.id)} />}
        </div>
      ) : (
        <div className="flex-1 overflow-y-auto px-4 py-3 text-xs">
          {tab === 'policies' && <HostPoliciesTab snapshotId={snapshotId} hostId={hostId} serverId={serverId} />}
          {tab === 'tags' && <HostTagsTab snapshotId={snapshotId} hostId={hostId} serverId={serverId} />}
          {(tab === 'overview' || tab === 'findings') && (
            <>
              {detail.isLoading && <div className="flex justify-center py-8"><Spinner /></div>}
              {errorMessage && <ErrorState message={errorMessage} onRetry={() => detail.refetch()} />}
              {h && tab === 'overview' && <HostOverview host={h} serverId={serverId} />}
              {h && tab === 'findings' && <HostFindings host={h} serverId={serverId} />}
            </>
          )}
        </div>
      )}
    </>
  )
}

/** Боковая панель хоста поверх списка: затемнение, `aside role="dialog"`, Esc закрывает (обработчик списка). Шире прежней — в ней таблицы. */
function HostDrawer({ hostId, snapshotId, serverId, onClose }: { hostId: string | null; snapshotId: number | undefined; serverId: number; onClose: () => void }) {
  const open = hostId !== null
  return (
    <>
      <div className={cn('fixed inset-0 z-30 bg-black/50 transition-opacity duration-200', open ? 'opacity-100' : 'pointer-events-none opacity-0')} onClick={onClose} aria-hidden />
      <aside role="dialog" aria-label="Хост" aria-hidden={!open} className={cn('fixed top-0 right-0 z-40 flex h-full w-[960px] max-w-[calc(100vw-2rem)] flex-col border-l border-grid bg-surface transition-transform duration-200', open ? 'translate-x-0' : 'translate-x-full')}>
        {hostId !== null && snapshotId !== undefined && <HostDrawerBody key={hostId} hostId={hostId} snapshotId={snapshotId} serverId={serverId} onClose={onClose} />}
      </aside>
    </>
  )
}

/** Инвентарь хостов снапшота: по умолчанию — последнего снапшота сервера. */
export function HostsPage({ serverId }: { serverId: number }) {
  const params = useSearchParams()
  const servers = useServers()
  const server = servers.data?.find((s) => s.id === serverId)
  const snapshotId = server?.last_snapshot_id ?? undefined
  const [filters, setFilters] = useState<HostFilters>(() => ({
    group: listFrom(params, 'group'),
    product: listFrom(params, 'product'),
    agent: listFrom<HostAgent>(params, 'agent', Object.keys(AGENT_LABELS) as HostAgent[]),
    protection: listFrom<HostProtection>(params, 'protection', Object.keys(PROTECTION_LABELS) as HostProtection[]),
    bases: listFrom<HostBases>(params, 'bases', Object.keys(BASES_LABELS) as HostBases[]),
    in_ad: listFrom(params, 'in_ad'),
    status: listFrom(params, 'status'),
    status_reason: listFrom(params, 'status_reason'),
    component: listFrom(params, 'component'),
    // Состояние без компонента сервер отвергает (422), поэтому из адреса оно читается только вместе с компонентом.
    component_state: params.get('component') ? COMPONENT_STATES.find((c) => c.key === params.get('component_state'))?.key : undefined,
    tag: listFrom(params, 'tag'),
    policy: Number(params.get('policy')) || undefined,
  }))
  const [searchInput, setSearchInput] = useState('')
  const q = useDebouncedValue(searchInput, 250)
  const [selectedIndex, setSelectedIndex] = useState(0)
  const [openHostId, setOpenHostId] = useState<string | null>(null)
  const searchRef = useRef<HTMLInputElement>(null)
  const filtersPanel = useFiltersPanel('ksc-hosts')
  const policyName = usePolicy(snapshotId, filters.policy).data?.name

  const queryArgs = useMemo(() => ({ ...filters, q: q || undefined }), [filters, q])
  const query = useHosts(snapshotId, queryArgs)
  const items = useMemo(() => query.data?.pages.flatMap((p) => p.items) ?? [], [query.data])
  const first = query.data?.pages[0]
  const total = first?.total ?? 0
  const tagsCollected = first?.tags_collected ?? false
  // Память фасетов — на странице, а не в панели: панель по умолчанию закрыта и при закрытии забывала бы значения.
  const remembered: HostRemembered = useRememberedFacets(first?.facets ? hostFacetValues(first.facets) : undefined)
  useEffect(() => setSelectedIndex(0), [queryArgs, snapshotId])
  const selected: Host | null = items[selectedIndex] ?? null

  function toggle<K extends keyof HostFilters>(key: K, value: HostFilters[K]) { setFilters((prev) => ({ ...prev, [key]: value })) }
  // Состояние без компонента сервер отвергает (422): снят последний компонент — снимается и состояние.
  function setComponent(names: string[] | undefined) { setFilters((prev) => ({ ...prev, component: names, component_state: names ? prev.component_state : undefined })) }
  function clearAll() { setFilters({}); setSearchInput('') }
  // Что выбрано, пока панель свёрнута: фильтр из ссылки не должен действовать незаметно.
  // Чип на каждое выбранное значение: крестик снимает только его.
  const chips: FilterChip[] = [
    ...valueChips('Защита', filters.protection, (p) => PROTECTION_LABELS[p], (v) => toggle('protection', v)),
    ...valueChips('Агент', filters.agent, (a) => AGENT_LABELS[a], (v) => toggle('agent', v)),
    ...valueChips('Базы', filters.bases, (b) => BASES_LABELS[b], (v) => toggle('bases', v)),
    ...valueChips('AD', filters.in_ad, (k) => IN_AD_LABELS[k] ?? k, (v) => toggle('in_ad', v)),
    ...valueChips('Статус KSC', filters.status, (s) => KSC_STATUS_LABELS[s] ?? s, (v) => toggle('status', v)),
    ...valueChips('Причина статуса', filters.status_reason, (r) => r, (v) => toggle('status_reason', v)),
    ...valueChips('Компонент', filters.component, (c) => c, setComponent),
  ]
  if (filters.component_state) chips.push({ label: `Состояние компонента: ${COMPONENT_STATE_LABELS[filters.component_state]}`, clear: () => toggle('component_state', undefined) })
  chips.push(...valueChips('Тег', filters.tag, (t) => (t === '-' ? 'без тегов' : t), (v) => toggle('tag', v)))
  if (filters.policy) chips.push({ label: `политика #${filters.policy}${policyName ? ` · ${policyName}` : ''}`, clear: () => toggle('policy', undefined) })
  chips.push(...valueChips('Группа', filters.group, (g) => g, (v) => toggle('group', v)))
  chips.push(...valueChips('Продукт', filters.product, (p) => p, (v) => toggle('product', v)))

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        // В поле ввода (в том числе в поиске таблиц внутри панели хоста) Esc сначала снимает фокус, панель закрывает второй Esc.
        if (isTypingTarget(e.target) && document.activeElement instanceof HTMLElement) return document.activeElement.blur()
        if (openHostId !== null) return setOpenHostId(null)
        if (document.activeElement instanceof HTMLElement) document.activeElement.blur()
        return
      }
      // Панель хоста открыта: клавиши списка (Enter, j/k, /) не действуют — иначе Enter на кнопке или ссылке внутри панели заново открыл бы выбранный хост.
      if (openHostId !== null || isTypingTarget(e.target)) return
      if (e.key === '/') { e.preventDefault(); searchRef.current?.focus(); return }
      if (e.key === 'j') { e.preventDefault(); setSelectedIndex((i) => Math.min(items.length - 1, i + 1)); return }
      if (e.key === 'k') { e.preventDefault(); setSelectedIndex((i) => Math.max(0, i - 1)); return }
      if (e.key === 'Enter' && selected) { e.preventDefault(); setOpenHostId(selected.host_id) }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [items.length, selected, openHostId])

  const hasFilters = Object.values(filters).some((v) => v !== undefined) || q !== ''
  const errorMessage = query.error instanceof ApiRequestError ? query.error.message : query.isError ? 'Не удалось загрузить хосты' : null
  if (servers.isLoading) return <FullPageSpinner />
  if (snapshotId === undefined) {
    return <div className="p-6"><EmptyState icon={FilterX} title="Снапшотов нет" description="Загрузите выгрузку или запустите сбор из KSC в настройках модуля." /></div>
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex shrink-0 flex-wrap items-center gap-3 border-b border-grid bg-surface px-4 py-2.5">
        <h1 className="text-sm font-semibold text-text">Хосты</h1>
        <span className="font-mono text-xs text-text-secondary">снапшот #{snapshotId}</span>
        <FiltersButton open={filtersPanel.open} onToggle={filtersPanel.toggle} count={chips.length} />
        <ExportButton href={exportHref(`/api/ksc/snapshots/${snapshotId}/hosts/export`, queryArgs)} total={first?.total} disabled={query.isLoading} />
        <div className="relative max-w-sm flex-1">
          <Search size={14} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-text-secondary" aria-hidden />
          <input ref={searchRef} value={searchInput} onChange={(e) => setSearchInput(e.target.value)} placeholder="Имя, IP, ОС… (/)" className="w-full rounded border border-border bg-app-bg py-1.5 pr-3 pl-8 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" />
        </div>
        {hasFilters && <button type="button" onClick={clearAll} className="flex items-center gap-1.5 rounded px-2 py-1 text-xs text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"><FilterX size={13} aria-hidden /> Сбросить</button>}
        <div className="font-mono text-xs tabular-nums text-text-secondary">{query.data ? (items.length < total ? `${items.length} из ${total}` : total) : '…'}</div>
        {!filtersPanel.open && <FilterChips chips={chips} />}
      </header>
      <div className="flex min-h-0 flex-1">
        {filtersPanel.open && <HostFacetPanel facets={first?.facets ?? null} remembered={remembered} filters={filters} onToggle={toggle} onComponent={setComponent} tagsCollected={tagsCollected} total={total} />}
        <div className="min-w-0 flex-1 bg-app-bg">
          {query.isLoading && <FullPageSpinner />}
          {errorMessage && <div className="p-6"><ErrorState message={errorMessage} onRetry={() => query.refetch()} /></div>}
          {!query.isLoading && !errorMessage && items.length === 0 && (
            <div className="p-6"><EmptyState icon={FilterX} title={hasFilters ? 'Ничего не найдено' : 'Хостов нет'} description={hasFilters ? 'Ни один хост не подходит под фильтры.' : 'В снапшоте нет хостов.'} /></div>
          )}
          {!query.isLoading && !errorMessage && items.length > 0 && (
            <HostsTable items={items} selectedIndex={selectedIndex} onSelectIndex={setSelectedIndex} onOpen={(i) => setOpenHostId(items[i].host_id)} onReachEnd={() => { if (query.hasNextPage && !query.isFetchingNextPage) query.fetchNextPage() }} serverId={serverId} tagsCollected={tagsCollected} />
          )}
        </div>
      </div>
      <HostDrawer hostId={openHostId} snapshotId={snapshotId} serverId={serverId} onClose={() => setOpenHostId(null)} />
    </div>
  )
}
