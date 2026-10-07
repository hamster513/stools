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
import { FiltersButton, FilterChips, type FilterChip } from '@/platform/filters/FiltersBar'
import { useFiltersPanel } from '@/platform/filters/useFiltersPanel'
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

type HostFilters = Pick<HostsQuery, 'group' | 'product' | 'agent' | 'protection' | 'bases' | 'in_ad' | 'status' | 'component' | 'component_state' | 'tag' | 'policy'>

const COMPONENT_STATES: { key: ComponentState; label: string }[] = [
  { key: 'on', label: 'работает' },
  { key: 'off', label: 'не работает' },
  { key: 'other', label: 'прочее' },
  { key: 'none', label: 'нет компонента' },
]
const COMPONENT_STATE_LABELS = Object.fromEntries(COMPONENT_STATES.map((c) => [c.key, c.label])) as Record<ComponentState, string>

/** Ширины колонок таблицы хостов в пикселях (классы w-*) — минимальная ширина строки считается из них. */
const BASE_COLUMNS_WIDTH = 1312
const TAGS_COLUMN_WIDTH = 192
/** Стрелка в конце строки: 14 px и отступ 8 px. */
const CHEVRON_WIDTH = 22
const TAGS_SHOWN = 3

function isTypingTarget(el: EventTarget | null): boolean {
  return el instanceof HTMLElement && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable)
}

function HostFacetPanel({ facets, filters, onToggle, onComponent, tagsCollected, total }: {
  facets: HostsResponse['facets']
  filters: HostFilters
  onToggle: <K extends keyof HostFilters>(key: K, value: HostFilters[K]) => void
  onComponent: (name: string | undefined) => void
  tagsCollected: boolean
  total: number
}) {
  const groups = Object.entries(facets?.group ?? {}).sort((a, b) => b[1] - a[1])
  const products = Object.entries(facets?.product ?? {}).sort((a, b) => b[1] - a[1])
  const hasAd = Object.keys(facets?.in_ad ?? {}).length > 0
  // Выбранный компонент остаётся в списке, даже если под «нет компонента» его не осталось ни у одного хоста.
  const componentFacet = facets?.component ?? {}
  const components = Object.keys(componentFacet).concat(filters.component && !(filters.component in componentFacet) ? [filters.component] : [])
    .sort((a, b) => (componentFacet[b]?.off ?? 0) - (componentFacet[a]?.off ?? 0) || a.localeCompare(b, 'ru'))
  const tags = Object.entries(facets?.tag ?? {}).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0], 'ru'))
  return (
    <div className="flex h-full w-64 shrink-0 flex-col overflow-y-auto border-r border-grid bg-surface">
      <div className="border-b border-grid px-4 py-3 text-xs text-text-secondary">Хостов <span className="font-mono tabular-nums text-text">{total}</span></div>
      <FacetSection title="Защита">
        {(Object.keys(PROTECTION_LABELS) as HostProtection[]).map((p) => (
          <FacetRow key={p} active={filters.protection === p} count={facets?.protection[p] ?? 0} onClick={() => onToggle('protection', filters.protection === p ? undefined : p)}>{PROTECTION_LABELS[p]}</FacetRow>
        ))}
      </FacetSection>
      <FacetSection title="Агент">
        {(Object.keys(AGENT_LABELS) as HostAgent[]).map((a) => (
          <FacetRow key={a} active={filters.agent === a} count={facets?.agent[a] ?? 0} onClick={() => onToggle('agent', filters.agent === a ? undefined : a)}>{AGENT_LABELS[a]}</FacetRow>
        ))}
      </FacetSection>
      <FacetSection title="Базы">
        {(Object.keys(BASES_LABELS) as HostBases[]).map((b) => (
          <FacetRow key={b} active={filters.bases === b} count={facets?.bases[b] ?? 0} onClick={() => onToggle('bases', filters.bases === b ? undefined : b)}>{BASES_LABELS[b]}</FacetRow>
        ))}
      </FacetSection>
      {hasAd && (
        <FacetSection title="AD">
          {Object.entries(facets?.in_ad ?? {}).map(([k, n]) => (
            <FacetRow key={k} active={filters.in_ad === k} count={n} onClick={() => onToggle('in_ad', filters.in_ad === k ? undefined : k)}>{IN_AD_LABELS[k] ?? k}</FacetRow>
          ))}
        </FacetSection>
      )}
      <FacetSection title="Статус KSC">
        {(['ok', 'warning', 'critical'] as const).map((s) => (
          <FacetRow key={s} active={filters.status === s} count={facets?.status[s] ?? 0} onClick={() => onToggle('status', filters.status === s ? undefined : s)}>{s === 'ok' ? 'ок' : s === 'warning' ? 'предупреждение' : 'критично'}</FacetRow>
        ))}
      </FacetSection>
      <FacetSection title="Компонент защиты">
        <div className="mb-1 px-2 text-[10px] text-text-secondary">число — хостов, где компонент не работает</div>
        {components.map((name) => (
          <div key={name}>
            <FacetRow active={filters.component === name} count={componentFacet[name]?.off ?? 0} onClick={() => onComponent(filters.component === name ? undefined : name)}>{name}</FacetRow>
            {filters.component === name && (
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
          <FacetRow active={filters.tag === '-'} onClick={() => onToggle('tag', filters.tag === '-' ? undefined : '-')}>без тегов</FacetRow>
          {tags.map(([t, n]) => (
            <FacetRow key={t} active={filters.tag === t} count={n} onClick={() => onToggle('tag', filters.tag === t ? undefined : t)}>{t}</FacetRow>
          ))}
        </FacetSection>
      )}
      <FacetSection title="Группа">
        {groups.map(([g, n]) => (
          <FacetRow key={g} active={filters.group === g} count={n} onClick={() => onToggle('group', filters.group === g ? undefined : g)}>{g}</FacetRow>
        ))}
      </FacetSection>
      <FacetSection title="Продукт">
        {products.map(([p, n]) => (
          <FacetRow key={p} active={filters.product === p} count={n} onClick={() => onToggle('product', filters.product === p ? undefined : p)}>{p}</FacetRow>
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

function HostsTable({ items, selectedIndex, onSelectIndex, onOpen, onReachEnd, serverId, tagsCollected }: { items: Host[]; selectedIndex: number; onSelectIndex: (i: number) => void; onOpen: (i: number) => void; onReachEnd?: () => void; serverId: number; tagsCollected: boolean }) {
  const { parentRef, rows, totalSize } = useVirtualRows(items.length, ROW_HEIGHT, selectedIndex, onReachEnd)
  const minWidth = BASE_COLUMNS_WIDTH + CHEVRON_WIDTH + (tagsCollected ? TAGS_COLUMN_WIDTH : 0)

  return (
    <div ref={parentRef} className="h-full overflow-auto">
      <div style={{ minWidth }} className="sticky top-0 z-10 flex border-b border-grid bg-surface text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
        <div className="w-56 shrink-0 px-2 py-2">Хост</div>
        <div className="w-40 shrink-0 px-2 py-2">Группа</div>
        {tagsCollected && <div className="w-48 shrink-0 px-2 py-2">Теги</div>}
        <div className="w-40 shrink-0 px-2 py-2">ОС</div>
        <div className="w-32 shrink-0 px-2 py-2">Агент</div>
        <div className="w-40 shrink-0 px-2 py-2">Защита</div>
        <div className="w-32 shrink-0 px-2 py-2">Базы</div>
        <div className="w-28 shrink-0 px-2 py-2">Полный поиск</div>
        <div className="w-16 shrink-0 px-2 py-2 text-right">Угрозы</div>
        <div className="w-24 shrink-0 px-2 py-2">AD</div>
        <div className="w-20 shrink-0 px-2 py-2 text-right">Находок</div>
      </div>
      <div style={{ height: totalSize, position: 'relative' }}>
        {rows.map((v) => {
          const h = items[v.index]
          const selected = v.index === selectedIndex
          return (
            <div key={h.id} {...clickableRow(() => { onSelectIndex(v.index); onOpen(v.index) })} className={cn(ROW_FOCUS, 'absolute top-0 left-0 flex w-full cursor-pointer items-center border-b border-grid text-xs', selected ? 'bg-row-selected' : 'hover:bg-row-hover')} style={{ height: ROW_HEIGHT, minWidth, transform: `translateY(${v.start}px)` }}>
              <div className="w-56 shrink-0 truncate px-2">
                <div className="truncate text-text" title={h.name}>{h.name}</div>
                <div className="truncate text-[10px] text-text-secondary" title={h.fqdn}>{h.fqdn}</div>
              </div>
              <div className="w-40 shrink-0 truncate px-2 text-text-secondary" title={h.group}>{h.group}</div>
              {tagsCollected && <div className="w-48 shrink-0 px-2"><TagChips tags={h.tags ?? []} /></div>}
              <div className="w-40 shrink-0 truncate px-2 text-text-secondary" title={h.os}>{h.os}</div>
              <div className="w-32 shrink-0 truncate px-2 text-text-secondary">{AGENT_LABELS[h.agent]}{h.agent_version ? ` · ${h.agent_version}` : ''}</div>
              <div className={cn('w-40 shrink-0 truncate px-2', h.protection === 'off' ? 'text-risk-high' : 'text-text-secondary')}>
                {PROTECTION_LABELS[h.protection]}{h.protection === 'off' ? ` · ${RTP_STATE_LABELS[h.rtp_state] ?? h.rtp_state}` : ''}
              </div>
              <div className={cn('w-32 shrink-0 truncate px-2', h.bases === 'old' && 'text-risk-high')}>{h.bases_at ? new Date(h.bases_at).toLocaleDateString('ru-RU') : '—'} · {BASES_LABELS[h.bases]}</div>
              <div className="w-28 shrink-0 truncate px-2 text-text-secondary">{h.last_fullscan_at ? new Date(h.last_fullscan_at).toLocaleDateString('ru-RU') : 'никогда'}</div>
              <div className={cn('w-16 shrink-0 px-2 text-right font-mono tabular-nums', h.threats > 0 && 'text-risk-high')}>{h.threats}</div>
              <div className="w-24 shrink-0 truncate px-2 text-text-secondary">{h.in_ad ? IN_AD_LABELS[h.in_ad] : '—'}</div>
              <div role="presentation" className="w-20 shrink-0 px-2 text-right" onClick={(e) => e.stopPropagation()} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') e.stopPropagation() }}>
                {h.findings > 0 ? (
                  <Link to={`/ksc/servers/${serverId}/findings?q=${encodeURIComponent(h.name)}`} className="font-mono tabular-nums text-text hover:text-primary">{h.findings}</Link>
                ) : (
                  <span className="font-mono tabular-nums text-text-secondary">0</span>
                )}
              </div>
              <ChevronRight size={14} className="mr-2 ml-auto shrink-0 text-text-secondary/40" aria-hidden />
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
          {tab === 'exclusions' && <ExclusionsTable snapshotId={snapshotId} serverId={serverId} hostId={hostId} />}
          {tab === 'netrules' && <NetRulesTable snapshotId={snapshotId} serverId={serverId} hostId={hostId} />}
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
    group: params.get('group') ?? undefined,
    product: params.get('product') ?? undefined,
    agent: (params.get('agent') as HostFilters['agent']) ?? undefined,
    protection: (params.get('protection') as HostFilters['protection']) ?? undefined,
    bases: (params.get('bases') as HostFilters['bases']) ?? undefined,
    in_ad: params.get('in_ad') ?? undefined,
    status: params.get('status') ?? undefined,
    component: params.get('component') ?? undefined,
    // Состояние без компонента сервер отвергает (422), поэтому из адреса оно читается только вместе с компонентом.
    component_state: params.get('component') ? COMPONENT_STATES.find((c) => c.key === params.get('component_state'))?.key : undefined,
    tag: params.get('tag') ?? undefined,
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
  useEffect(() => setSelectedIndex(0), [queryArgs, snapshotId])
  const selected: Host | null = items[selectedIndex] ?? null

  function toggle<K extends keyof HostFilters>(key: K, value: HostFilters[K]) { setFilters((prev) => ({ ...prev, [key]: value })) }
  function setComponent(name: string | undefined) { setFilters((prev) => ({ ...prev, component: name, component_state: undefined })) }
  function clearAll() { setFilters({}); setSearchInput('') }
  // Что выбрано, пока панель свёрнута: фильтр из ссылки не должен действовать незаметно.
  const chips: FilterChip[] = []
  if (filters.protection) chips.push({ label: `защита ${PROTECTION_LABELS[filters.protection]}`, clear: () => toggle('protection', undefined) })
  if (filters.agent) chips.push({ label: `агент ${AGENT_LABELS[filters.agent]}`, clear: () => toggle('agent', undefined) })
  if (filters.bases) chips.push({ label: `базы ${BASES_LABELS[filters.bases]}`, clear: () => toggle('bases', undefined) })
  if (filters.in_ad) chips.push({ label: `AD ${IN_AD_LABELS[filters.in_ad] ?? filters.in_ad}`, clear: () => toggle('in_ad', undefined) })
  if (filters.status) chips.push({ label: `статус KSC ${({ ok: 'ок', warning: 'предупреждение', critical: 'критично' } as Record<string, string>)[filters.status] ?? filters.status}`, clear: () => toggle('status', undefined) })
  if (filters.component) chips.push({ label: `компонент ${filters.component}${filters.component_state ? ` · ${COMPONENT_STATE_LABELS[filters.component_state]}` : ''}`, clear: () => setComponent(undefined) })
  if (filters.tag) chips.push({ label: filters.tag === '-' ? 'без тегов' : `тег ${filters.tag}`, clear: () => toggle('tag', undefined) })
  if (filters.policy) chips.push({ label: `политика #${filters.policy}${policyName ? ` · ${policyName}` : ''}`, clear: () => toggle('policy', undefined) })
  if (filters.group) chips.push({ label: `группа ${filters.group}`, clear: () => toggle('group', undefined) })
  if (filters.product) chips.push({ label: `продукт ${filters.product}`, clear: () => toggle('product', undefined) })

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') { if (openHostId !== null) return setOpenHostId(null); if (document.activeElement instanceof HTMLElement) document.activeElement.blur(); return }
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
        <div className="relative max-w-sm flex-1">
          <Search size={14} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-text-secondary" aria-hidden />
          <input ref={searchRef} value={searchInput} onChange={(e) => setSearchInput(e.target.value)} placeholder="Имя, IP, ОС… (/)" className="w-full rounded border border-border bg-app-bg py-1.5 pr-3 pl-8 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" />
        </div>
        {hasFilters && <button type="button" onClick={clearAll} className="flex items-center gap-1.5 rounded px-2 py-1 text-xs text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"><FilterX size={13} aria-hidden /> Сбросить</button>}
        <div className="font-mono text-xs tabular-nums text-text-secondary">{query.data ? (items.length < total ? `${items.length} из ${total}` : total) : '…'}</div>
        {!filtersPanel.open && <FilterChips chips={chips} />}
      </header>
      <div className="flex min-h-0 flex-1">
        {filtersPanel.open && <HostFacetPanel facets={first?.facets ?? null} filters={filters} onToggle={toggle} onComponent={setComponent} tagsCollected={tagsCollected} total={total} />}
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
