import { useEffect, useMemo, useRef, useState } from 'react'
import { Download, FilterX, Search, X } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { exportUrl, useHost, useVulns } from '@/modules/vm/api/queries'
import { AssetLink } from '@/modules/assets/AssetLink'
import type { RiskLevel, VulnItem, VulnSort } from '@/modules/vm/api/types'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
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

/** Главный экран модуля: плоская таблица пар хост–CVE с фасетами и картой расчёта. */
export function VulnsPage() {
  const params = useSearchParams()
  const { navigate } = useRouter()
  // Адрес задаёт начальные фильтры: сюда ведут ссылки с обзора и из карточки.
  const [filters, setFilters] = useState<VulnFilters>(() => ({
    level: (params.get('level') as RiskLevel | null) ?? undefined,
    zone: params.get('zone') ?? undefined,
    criticality: params.get('criticality') ?? undefined,
    cvss_source: (params.get('cvss_source') as VulnFilters['cvss_source']) ?? undefined,
    exploits: params.get('exploits') === 'true' ? true : undefined,
  }))
  const cveParam = params.get('cve') ?? undefined
  const hostIdParam = params.get('host_id') ? Number(params.get('host_id')) : undefined
  const [sort, setSort] = useState<VulnSort>(() => {
    const s = params.get('sort') as VulnSort | null
    return s && SORTS.includes(s) ? s : 'risk_desc'
  })
  const [searchInput, setSearchInput] = useState('')
  const q = useDebouncedValue(searchInput, 250)
  const [selectedIndex, setSelectedIndex] = useState(0)
  const [openKey, setOpenKey] = useState<string | null>(null)
  const searchRef = useRef<HTMLInputElement>(null)

  const host = useHost(hostIdParam)
  const queryArgs = useMemo(
    () => ({ ...filters, q: q || undefined, cve: cveParam, host_id: hostIdParam, sort }),
    [filters, q, cveParam, hostIdParam, sort],
  )
  const query = useVulns(queryArgs)
  const items = useMemo(() => query.data?.pages.flatMap((p) => p.items) ?? [], [query.data])
  const facets = query.data?.pages[0]?.facets ?? undefined
  const total = query.data?.pages[0]?.total ?? 0

  useEffect(() => setSelectedIndex(0), [queryArgs])

  const selected: VulnItem | null = items[selectedIndex] ?? null
  const openItem = items.find((i) => `${i.host_id}:${i.cve_id}` === openKey) ?? null

  function toggle<K extends keyof VulnFilters>(key: K, value: VulnFilters[K]) {
    setFilters((prev) => ({ ...prev, [key]: value }))
  }
  function clearAll() {
    setFilters({})
    setSearchInput('')
    if (cveParam || hostIdParam) navigate('/vm/vulns', { replace: true })
  }

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
      if (e.key === 'Enter' && selected) { e.preventDefault(); setOpenKey(`${selected.host_id}:${selected.cve_id}`) }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [items.length, selected, openKey])

  const hasFilters = Object.values(filters).some((v) => v !== undefined) || q !== '' || !!cveParam || hostIdParam !== undefined
  const errorMessage = query.error instanceof ApiRequestError ? query.error.message : query.isError ? 'Не удалось загрузить уязвимости' : null

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex shrink-0 items-center gap-3 border-b border-grid bg-surface px-4 py-2.5">
        <h1 className="text-sm font-semibold text-text">Уязвимости</h1>
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
        <a
          href={exportUrl(queryArgs)}
          className="flex items-center gap-1.5 rounded border border-border px-2 py-1 text-xs text-text hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
          title="Скачать текущую выборку как CSV"
        >
          <Download size={13} aria-hidden /> CSV
        </a>
        <div className="font-mono text-xs tabular-nums text-text-secondary">
          {query.data ? (items.length < total ? `${items.length.toLocaleString('ru-RU')} из ${total.toLocaleString('ru-RU')}` : total.toLocaleString('ru-RU')) : '…'}
        </div>
      </header>

      <div className="flex min-h-0 flex-1">
        <FacetPanel facets={facets} filters={filters} onToggle={toggle} total={total} />
        <div className="min-w-0 flex-1 bg-app-bg">
          {query.isLoading && <FullPageSpinner />}
          {errorMessage && <div className="p-6"><ErrorState message={errorMessage} onRetry={() => query.refetch()} /></div>}
          {!query.isLoading && !errorMessage && items.length === 0 && (
            <div className="p-6">
              <EmptyState
                icon={FilterX}
                title={hasFilters ? 'Ничего не найдено' : 'Уязвимостей ещё нет'}
                description={hasFilters ? 'Ни одна пара не подходит под фильтры. Сбросьте их или измените запрос.' : 'Импортируйте хосты из MaxPatrol VM в настройках модуля.'}
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
              onOpen={(i) => setOpenKey(`${items[i].host_id}:${items[i].cve_id}`)}
              onReachEnd={() => {
                if (query.hasNextPage && !query.isFetchingNextPage) query.fetchNextPage()
              }}
            />
          )}
        </div>
      </div>

      <RiskDrawer item={openItem} onClose={() => setOpenKey(null)} />
    </div>
  )
}
