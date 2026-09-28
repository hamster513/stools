import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import type { InfiniteData, UseInfiniteQueryResult } from '@tanstack/react-query'
import { FilterX, Search } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { useSearchParams } from '@/lib/router'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { FacetPanel } from './FacetPanel'
import type { FindingsTableProps } from './FindingsTable'
import type { FindingBase, FindingFilters, FindingsQuery, FindingsResponse, FindingStatus, Severity } from './types'

function isTypingTarget(el: EventTarget | null): boolean {
  return el instanceof HTMLElement && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable)
}

/**
 * Находки снапшота: по умолчанию — последнего снапшота области (домена,
 * сервера). Фасеты, поиск, клавиши j/k, «/», Enter, Esc. useFindings — хук
 * модуля: его аргументы собирает страница из фильтров и поиска.
 */
export function CollectorFindingsPage<F extends FindingBase>({ loading, lastSnapshotId, useFindings, searchFromUrl = false, searchPlaceholder, emptyDescription, table, drawer }: {
  loading: boolean
  lastSnapshotId: number | undefined
  useFindings: (snapshotId: number | undefined, query: Omit<FindingsQuery, 'limit' | 'offset'>) => UseInfiniteQueryResult<InfiniteData<FindingsResponse<F>>, ApiRequestError>
  searchFromUrl?: boolean
  searchPlaceholder: string
  emptyDescription: string
  table: (props: FindingsTableProps<F>) => ReactNode
  drawer: (finding: F | null, snapshotId: number | undefined, onClose: () => void) => ReactNode
}) {
  const params = useSearchParams()
  const snapshotId = params.get('snapshot') ? Number(params.get('snapshot')) : lastSnapshotId
  const [filters, setFilters] = useState<FindingFilters>(() => ({
    check: params.get('check') ?? undefined,
    severity: (params.get('severity') as Severity | null) ?? undefined,
    status: (params.get('status') as FindingStatus | null) ?? undefined,
  }))
  const [searchInput, setSearchInput] = useState(searchFromUrl ? (params.get('q') ?? '') : '')
  const q = useDebouncedValue(searchInput, 250)
  const [selectedIndex, setSelectedIndex] = useState(0)
  const [openKey, setOpenKey] = useState<string | null>(null)
  const searchRef = useRef<HTMLInputElement>(null)

  const queryArgs = useMemo(() => ({ ...filters, q: q || undefined }), [filters, q])
  const query = useFindings(snapshotId, queryArgs)
  const items = useMemo(() => query.data?.pages.flatMap((p) => p.items) ?? [], [query.data])
  const first = query.data?.pages[0]
  const total = first?.total ?? 0
  useEffect(() => setSelectedIndex(0), [queryArgs, snapshotId])
  const selected: F | null = items[selectedIndex] ?? null
  const openItem = items.find((i) => i.key === openKey) ?? null

  function toggle<K extends keyof FindingFilters>(key: K, value: FindingFilters[K]) { setFilters((prev) => ({ ...prev, [key]: value })) }
  function clearAll() { setFilters({}); setSearchInput('') }

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') { if (openKey !== null) return setOpenKey(null); if (document.activeElement instanceof HTMLElement) document.activeElement.blur(); return }
      if (isTypingTarget(e.target)) return
      if (e.key === '/') { e.preventDefault(); searchRef.current?.focus(); return }
      if (e.key === 'j') { e.preventDefault(); setSelectedIndex((i) => Math.min(items.length - 1, i + 1)); return }
      if (e.key === 'k') { e.preventDefault(); setSelectedIndex((i) => Math.max(0, i - 1)); return }
      if (e.key === 'Enter' && selected) { e.preventDefault(); setOpenKey(selected.key) }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [items.length, selected, openKey])

  const hasFilters = Object.values(filters).some((v) => v !== undefined) || q !== ''
  const errorMessage = query.error instanceof ApiRequestError ? query.error.message : query.isError ? 'Не удалось загрузить находки' : null
  if (loading) return <FullPageSpinner />
  if (snapshotId === undefined) {
    return <div className="p-6"><EmptyState icon={FilterX} title="Снапшотов нет" description={emptyDescription} /></div>
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex shrink-0 items-center gap-3 border-b border-grid bg-surface px-4 py-2.5">
        <h1 className="text-sm font-semibold text-text">Находки</h1>
        <span className="font-mono text-xs text-text-secondary">снапшот #{snapshotId}</span>
        <div className="relative max-w-sm flex-1">
          <Search size={14} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-text-secondary" aria-hidden />
          <input ref={searchRef} value={searchInput} onChange={(e) => setSearchInput(e.target.value)} placeholder={searchPlaceholder} className="w-full rounded border border-border bg-app-bg py-1.5 pr-3 pl-8 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" />
        </div>
        {hasFilters && <button type="button" onClick={clearAll} className="flex items-center gap-1.5 rounded px-2 py-1 text-xs text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"><FilterX size={13} aria-hidden /> Сбросить</button>}
        {first?.compared_to.previous_id && <span className="text-[11px] text-text-secondary">к #{first.compared_to.previous_id}: <span className="text-risk-high">+{first.compared_to.new}</span> / <span className="text-kind-accepted">−{first.compared_to.fixed}</span></span>}
        <div className="font-mono text-xs tabular-nums text-text-secondary">{query.data ? (items.length < total ? `${items.length} из ${total}` : total) : '…'}</div>
      </header>
      <div className="flex min-h-0 flex-1">
        <FacetPanel facets={first?.facets ?? null} titles={first?.check_titles ?? {}} filters={filters} onToggle={toggle} total={total} />
        <div className="min-w-0 flex-1 bg-app-bg">
          {query.isLoading && <FullPageSpinner />}
          {errorMessage && <div className="p-6"><ErrorState message={errorMessage} onRetry={() => query.refetch()} /></div>}
          {!query.isLoading && !errorMessage && items.length === 0 && (
            <div className="p-6"><EmptyState icon={FilterX} title={hasFilters ? 'Ничего не найдено' : 'Находок нет'} description={hasFilters ? 'Ни одна находка не подходит под фильтры.' : 'Проверки ничего не нашли в этом снапшоте.'} /></div>
          )}
          {!query.isLoading && !errorMessage && items.length > 0 && (
            table({ items, selectedIndex, onSelectIndex: setSelectedIndex, onOpen: (i) => setOpenKey(items[i].key), onReachEnd: () => { if (query.hasNextPage && !query.isFetchingNextPage) query.fetchNextPage() } })
          )}
        </div>
      </div>
      {drawer(openItem, snapshotId, () => setOpenKey(null))}
    </div>
  )
}
