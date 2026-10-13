import { useEffect, useMemo, useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { FilterX, Search, X } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useMe } from '@/api/auth'
import { useCancelJob, useHost, useJob, useVulns } from '@/modules/vm/api/queries'
import { AssetLink } from '@/modules/assets/AssetLink'
import { CVSS_SOURCE_LABELS, LEVEL_LABELS, LEVELS, type CvssSource, type RiskLevel, type VulnItem, type VulnSort, type VulnsQuery } from '@/modules/vm/api/types'
import { ExportButton } from '@/platform/filters/ExportButton'
import { exportHref } from '@/platform/filters/exportHref'
import { facetValues, useRememberedFacets } from '@/platform/filters/useRememberedFacets'
import { FiltersButton, FilterChips, type FilterChip } from '@/platform/filters/FiltersBar'
import { useFiltersPanel } from '@/platform/filters/useFiltersPanel'
import { BulkBar } from '@/platform/findings/BulkBar'
import { findingFacetChips, fromWire, listFrom, toWire, valueChips } from '@/platform/findings/facets'
import { useUsersDirectory } from '@/platform/findings/queries'
import { STATUSES, type FindingStatus } from '@/platform/findings/types'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { useCan } from '@/lib/can'
import { useRouter, useSearchParams } from '@/lib/router'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { FacetPanel, type VulnFilters } from './vulns/FacetPanel'
import { VulnsTable } from './vulns/VulnsTable'
import { RiskDrawer } from './vulns/RiskDrawer'

function isTypingTarget(el: EventTarget | null): boolean {
  return el instanceof HTMLElement && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable)
}

const SORTS: VulnSort[] = ['risk_desc', 'risk_asc', 'cvss_desc', 'epss_desc', 'exploits_desc', 'host_asc', 'cve_asc']

/** Статусы из ссылки: коды через запятую или `all`; незнакомые коды отбрасываются. */
function statusesFrom(raw: string | null): FindingStatus[] | undefined {
  if (!raw) return undefined
  if (raw === 'all') return [...STATUSES]
  const picked = raw.split(',').filter((s): s is FindingStatus => (STATUSES as string[]).includes(s))
  return picked.length ? picked : undefined
}

/** Ключ пары `hostname|ip|cve` из ссылки («Мои находки»): CVE и IP — справа, имя — всё остальное. */
function splitKey(key: string | null): { hostname: string; cve: string } | null {
  const parts = key?.split('|') ?? []
  if (parts.length < 3) return null
  return { hostname: parts.slice(0, -2).join('|'), cve: parts[parts.length - 1] }
}

/**
 * Главный экран модуля: плоская таблица пар хост–CVE с фасетами и картой расчёта.
 * У пары — общий статус находки (platform/findings): по умолчанию показываются
 * открытые; галочки и полоса массовой смены, «выбрать всё по фильтру» меняет
 * пары фоновой задачей. `?key=` в адресе находит пару и открывает её карточку.
 */
export function VulnsPage() {
  const params = useSearchParams()
  const { navigate } = useRouter()
  const linked = splitKey(params.get('key'))
  // Адрес задаёт начальные фильтры: сюда ведут ссылки с обзора и из карточки.
  const [filters, setFilters] = useState<VulnFilters>(() => ({
    level: listFrom<RiskLevel>(params.get('level'), LEVELS),
    // `-` в адресе — «не задано» (пустое значение фасета).
    zone: fromWire(listFrom(params.get('zone'))),
    criticality: fromWire(listFrom(params.get('criticality'))),
    os: fromWire(listFrom(params.get('os'))),
    cvss_source: listFrom<CvssSource>(params.get('cvss_source'), Object.keys(CVSS_SOURCE_LABELS) as CvssSource[]),
    exploits: params.get('exploits') === 'true' ? true : undefined,
    // Пару по ссылке ищут при любом статусе: она могла быть закрыта.
    status: linked ? [...STATUSES] : statusesFrom(params.get('status')),
    assignee: listFrom(params.get('assignee')),
    overdue: params.get('overdue') === 'true' || undefined,
    risk_expiring: params.get('risk_expiring') === 'true' || undefined,
  }))
  const cveParam = params.get('cve') ?? linked?.cve ?? undefined
  const hostIdParam = params.get('host_id') ? Number(params.get('host_id')) : undefined
  const [sort, setSort] = useState<VulnSort>(() => {
    const s = params.get('sort') as VulnSort | null
    return s && SORTS.includes(s) ? s : 'risk_desc'
  })
  const [searchInput, setSearchInput] = useState(linked?.hostname ?? '')
  const q = useDebouncedValue(searchInput, 250)
  const [selectedIndex, setSelectedIndex] = useState(0)
  const [openKey, setOpenKey] = useState<string | null>(() => params.get('key'))
  const [checked, setChecked] = useState<ReadonlySet<string>>(new Set())
  const [anchor, setAnchor] = useState<number | null>(null)
  const [allByFilter, setAllByFilter] = useState(false)
  const [jobId, setJobId] = useState<number | undefined>(undefined)
  const searchRef = useRef<HTMLInputElement>(null)
  const filtersPanel = useFiltersPanel('vm-vulns')
  const { write } = useCan()
  const me = useMe()
  const directory = useUsersDirectory()
  const names = useMemo(() => new Map((directory.data ?? []).map((u) => [u.login, u.display_name || u.login])), [directory.data])
  const qc = useQueryClient()
  const job = useJob(jobId)
  const cancelJob = useCancelJob()

  const host = useHost(hostIdParam)
  // Без сортировки — фильтр списка как он есть: его же получает массовая смена «всё по фильтру».
  const listFilter = useMemo<Omit<VulnsQuery, 'limit' | 'offset' | 'sort'>>(() => {
    const { status, assignee, overdue, risk_expiring, ...data } = filters
    return {
      ...data, status: status?.join(','), assignee, overdue: overdue || undefined, risk_expiring: risk_expiring || undefined,
      q: q || undefined, cve: cveParam, host_id: hostIdParam,
    }
  }, [filters, q, cveParam, hostIdParam])
  // В адрес списка и выгрузки «не задано» уходит маркером `-`; массовая смена получает listFilter как есть — JSON-список с ''.
  const queryArgs = useMemo(() => ({
    ...listFilter, criticality: toWire(listFilter.criticality), zone: toWire(listFilter.zone), os: toWire(listFilter.os), sort,
  }), [listFilter, sort])
  const query = useVulns(queryArgs)
  const items = useMemo(() => query.data?.pages.flatMap((p) => p.items) ?? [], [query.data])
  const facets = query.data?.pages[0]?.facets ?? undefined
  const total = query.data?.pages[0]?.total ?? 0
  // Память фасетов — на странице, а не в панели: панель по умолчанию закрыта и при закрытии забывала бы значения.
  const remembered = useRememberedFacets(facets ? {
    zone: facetValues(facets.zone), os: facetValues(facets.os), assignee: facetValues(facets.assignee),
    criticality: facetValues(facets.criticality).filter((c) => c.count > 0),
  } : undefined)

  useEffect(() => { setSelectedIndex(0); setChecked(new Set()); setAnchor(null); setAllByFilter(false) }, [queryArgs])
  // Массовая смена закончилась — список и карточки уже другие (useJob обновляет данные модуля).
  const jobStatus = job.data?.status
  useEffect(() => {
    if (jobStatus && jobStatus !== 'running') { setChecked(new Set()); setAnchor(null); setAllByFilter(false) }
  }, [jobStatus])

  const selected: VulnItem | null = items[selectedIndex] ?? null
  const openItem = items.find((i) => i.key === openKey) ?? null

  function toggle<K extends keyof VulnFilters>(key: K, value: VulnFilters[K]) {
    setFilters((prev) => ({ ...prev, [key]: value }))
  }
  function clearAll() {
    setFilters({})
    setSearchInput('')
    if (cveParam || hostIdParam || linked) navigate('/vm/vulns', { replace: true })
  }
  function check(i: number, shift: boolean) {
    const on = !checked.has(items[i].key)
    const [from, to] = shift && anchor !== null ? [Math.min(anchor, i), Math.max(anchor, i)] : [i, i]
    const next = new Set(checked)
    for (const item of items.slice(from, to + 1)) {
      if (on) next.add(item.key)
      else next.delete(item.key)
    }
    setChecked(next)
    setAnchor(i)
    setAllByFilter(false)
  }
  function changed() {
    setChecked(new Set()); setAnchor(null); setAllByFilter(false)
    for (const key of ['vm-vulns', 'vm-overview']) qc.invalidateQueries({ queryKey: [key] })
  }
  // Что выбрано, пока панель свёрнута: фильтр из ссылки не должен действовать незаметно.
  // Чип на каждое значение; пустая строка — тоже значение фильтра («не задана», «без зоны»).
  const chips: FilterChip[] = findingFacetChips(filters, (next) => setFilters((prev) => ({ ...prev, ...next })), names)
  chips.push(...valueChips('Риск', filters.level, (l) => LEVEL_LABELS[l], (v) => toggle('level', v)))
  chips.push(...valueChips('Критичность', filters.criticality, (c) => c || 'не задана', (v) => toggle('criticality', v)))
  chips.push(...valueChips('Зона', filters.zone, (z) => z || 'без зоны', (v) => toggle('zone', v)))
  if (filters.exploits) chips.push({ label: 'есть эксплойт в ExploitDB', clear: () => toggle('exploits', undefined) })
  if (filters.msf) chips.push({ label: 'есть модуль Metasploit', clear: () => toggle('msf', undefined) })
  chips.push(...valueChips('Источник CVSS', filters.cvss_source, (c) => CVSS_SOURCE_LABELS[c], (v) => toggle('cvss_source', v)))
  chips.push(...valueChips('ОС', filters.os, (o) => o || 'не определена', (v) => toggle('os', v)))

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        if (openKey !== null) return setOpenKey(null)
        if (document.activeElement instanceof HTMLElement) document.activeElement.blur()
        return
      }
      if (isTypingTarget(e.target)) return
      if (e.key === '/') { e.preventDefault(); searchRef.current?.focus(); return }
      if (e.key === 'j') { e.preventDefault(); setSelectedIndex((i) => Math.min(items.length - 1, i + 1)); return }
      if (e.key === 'k') { e.preventDefault(); setSelectedIndex((i) => Math.max(0, i - 1)); return }
      if (e.key === 'Enter' && selected) { e.preventDefault(); setOpenKey(selected.key) }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [items.length, selected, openKey])

  const hasFilters = Object.values(filters).some((v) => v !== undefined) || q !== '' || !!cveParam || hostIdParam !== undefined
  const running = job.data?.status === 'running' ? job.data : null
  const errorMessage = query.error instanceof ApiRequestError ? query.error.message : query.isError ? 'Не удалось загрузить уязвимости' : null

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex shrink-0 flex-wrap items-center gap-3 border-b border-grid bg-surface px-4 py-2.5">
        <h1 className="text-sm font-semibold text-text">Уязвимости</h1>
        <FiltersButton open={filtersPanel.open} onToggle={filtersPanel.toggle} count={chips.length} />
        <ExportButton href={exportHref('/api/vm/export', queryArgs)} total={query.data?.pages[0]?.total} disabled={query.isLoading} />
        {cveParam && (
          <span className="inline-flex items-center gap-1 rounded border border-grid px-2 py-0.5 font-mono text-xs text-text">
            {cveParam}
            <button type="button" onClick={() => navigate('/vm/vulns')} aria-label="Снять фильтр по CVE" className="text-text-secondary hover:text-text"><X size={11} aria-hidden /></button>
          </span>
        )}
        {hostIdParam !== undefined && (
          <span className="inline-flex items-center gap-1 rounded border border-grid px-2 py-0.5 font-mono text-xs text-text">
            {host.data?.host.hostname ?? `хост #${hostIdParam}`}
            <button type="button" onClick={() => navigate('/vm/vulns')} aria-label="Снять фильтр по хосту" className="text-text-secondary hover:text-text"><X size={11} aria-hidden /></button>
          </span>
        )}
        {host.data && <AssetLink source="vm" hostKey={`${host.data.host.hostname}|${host.data.host.ip}`} className="text-xs" />}
        <div className="relative max-w-sm flex-1">
          <Search size={14} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-text-secondary" aria-hidden />
          <input
            ref={searchRef}
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder="Хост, IP или CVE… (/)"
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
        {!filtersPanel.open && <FilterChips chips={chips} />}
      </header>

      {job.data && (
        <div className="flex shrink-0 items-center gap-3 border-b border-grid bg-surface px-4 py-1.5 text-[11px] text-text-secondary">
          <span className="text-text">Массовая смена статусов, задача #{job.data.id}:</span>
          {running
            ? <>
                <span className="font-mono tabular-nums">{running.processed.toLocaleString('ru-RU')} из {(running.total ?? 0).toLocaleString('ru-RU')}</span>
                <span>{running.message}</span>
                <button type="button" onClick={() => cancelJob.mutate(running.id)} disabled={running.cancel_requested} className="text-text underline disabled:no-underline disabled:opacity-60">{running.cancel_requested ? 'останавливается…' : 'остановить'}</button>
              </>
            : (() => {
                // Остановленная и упавшая задача пишет в message, сколько применено до остановки.
                const text = job.data.status === 'done' ? `готово: ${job.data.message}`
                  : job.data.status === 'cancelled' ? `остановлена: ${job.data.message}`
                  : `ошибка: ${job.data.error ?? ''} · ${job.data.message}`
                return <span className="min-w-0 truncate" title={text}>{text}</span>
              })()}
          {!running && <button type="button" onClick={() => setJobId(undefined)} aria-label="Скрыть" className="ml-auto text-text-secondary hover:text-text"><X size={12} aria-hidden /></button>}
        </div>
      )}
      {write && !running && (
        <BulkBar module="vm" scopeId={0} keys={[...checked]} total={total}
          onSelectAll={() => setAllByFilter(true)} filter={allByFilter ? listFilter : undefined}
          onJob={setJobId} onDone={changed} onClear={() => { setChecked(new Set()); setAllByFilter(false) }} />
      )}

      <div className="flex min-h-0 flex-1">
        {filtersPanel.open && <FacetPanel facets={facets} remembered={remembered} filters={filters} onToggle={toggle} total={total} myLogin={me.data?.login} names={names} />}
        <div className="min-w-0 flex-1 bg-app-bg">
          {query.isLoading && <FullPageSpinner />}
          {errorMessage && <div className="p-6"><ErrorState message={errorMessage} onRetry={() => query.refetch()} /></div>}
          {!query.isLoading && !errorMessage && items.length === 0 && (
            <div className="p-6">
              <EmptyState
                icon={FilterX}
                title={hasFilters ? 'Ничего не найдено' : 'Открытых уязвимостей нет'}
                description={hasFilters ? 'Ни одна пара не подходит под фильтры. Сбросьте их или измените запрос.' : 'Открытых пар хост–CVE нет: остальные — в фильтре по статусу. Если импорта ещё не было — импортируйте хосты из MaxPatrol VM в настройках модуля.'}
              />
            </div>
          )}
          {!query.isLoading && !errorMessage && items.length > 0 && (
            <VulnsTable
              items={items}
              selectedIndex={selectedIndex}
              sort={sort}
              onSort={setSort}
              onSelectIndex={setSelectedIndex}
              onOpen={(i) => setOpenKey(items[i].key)}
              onReachEnd={() => {
                if (query.hasNextPage && !query.isFetchingNextPage) query.fetchNextPage()
              }}
              {...(write ? { checked, onCheck: check, onCheckAll: (on: boolean) => { setChecked(on ? new Set(items.map((i) => i.key)) : new Set()); setAllByFilter(false) } } : {})}
            />
          )}
        </div>
      </div>

      <RiskDrawer item={openItem} onClose={() => setOpenKey(null)} onChanged={() => { for (const key of ['vm-vulns', 'vm-overview']) qc.invalidateQueries({ queryKey: [key] }) }} />
    </div>
  )
}
