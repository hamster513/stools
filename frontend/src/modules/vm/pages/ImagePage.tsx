import { useEffect, useMemo, useRef, useState } from 'react'
import { Check, Copy, FilterX, Search, ShieldCheck } from 'lucide-react'
import { ApiRequestError, buildQuery } from '@/api/client'
import { useImage, useImageVulns } from '@/modules/vm/api/queries'
import {
  IMAGE_LEVEL_LABELS, IMAGE_LEVELS, NO_RISK_TITLE, SCAN_STATUS_LABELS, TRIVY_SEVERITIES, TRIVY_SEVERITY_LABELS,
  type ImageDetail, type ImageVulnItem, type ImageVulnSort,
} from '@/modules/vm/api/types'
import { RiskBadge } from '@/modules/vm/components/RiskBadge'
import { ExportButton } from '@/platform/filters/ExportButton'
import { exportHref } from '@/platform/filters/exportHref'
import { FiltersButton, FilterChips, type FilterChip } from '@/platform/filters/FiltersBar'
import { useFiltersPanel } from '@/platform/filters/useFiltersPanel'
import { listFrom, valueChips } from '@/platform/findings/facets'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { cn } from '@/lib/cn'
import { Link, useRouter, useSearchParams } from '@/lib/router'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { date, megabytes } from './images/format'
import { ImageRiskDrawer } from './images/ImageRiskDrawer'
import { ImageVulnsFacetPanel, type ImageVulnFilters } from './images/ImageVulnsFacetPanel'
import { ImageVulnsTable } from './images/ImageVulnsTable'
import { TrivyCounts } from './images/TrivyCounts'

function isTypingTarget(el: EventTarget | null): boolean {
  return el instanceof HTMLElement && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable)
}

const SORTS: ImageVulnSort[] = ['risk_desc', 'severity_desc', 'package', 'cve']
const DEFAULT_SORT: ImageVulnSort = 'risk_desc'

/** Ключ находки: тройка (идентификатор, пакет, версия) — один CVE бывает в нескольких пакетах. */
function vulnKey(v: ImageVulnItem): string {
  return `${v.cve_id}|${v.package}|${v.installed_version}`
}

/**
 * Короткий digest с кнопкой «копировать»: в буфер уходит полный хеш. Буфер бывает закрыт
 * (нет https, отказ в разрешении) — тогда показывается полный digest, выделенный для ручного копирования.
 */
function DigestCopy({ short, full }: { short: string; full: string }) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle')
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined)
  const text = useRef<HTMLSpanElement>(null)
  useEffect(() => () => clearTimeout(timer.current), [])
  useEffect(() => {
    if (state !== 'failed' || !text.current) return
    const range = document.createRange()
    range.selectNodeContents(text.current)
    const selection = window.getSelection()
    selection?.removeAllRanges()
    selection?.addRange(range)
  }, [state])

  async function copy() {
    try {
      await navigator.clipboard.writeText(full)
      setState('copied')
      clearTimeout(timer.current)
      timer.current = setTimeout(() => setState('idle'), 1500)
    } catch {
      setState('failed')
    }
  }

  const message = state === 'copied' ? 'Digest скопирован' : state === 'failed' ? 'Не удалось скопировать — digest выделен, скопируйте вручную' : ''
  return (
    <span className="inline-flex items-center gap-1">
      <span ref={text} className="font-mono text-text" title={full}>{state === 'failed' ? full : short}</span>
      <button
        type="button"
        onClick={copy}
        aria-label="Копировать полный digest"
        title={message || 'Копировать полный digest'}
        className="rounded p-0.5 text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
      >
        {state === 'copied' ? <Check size={12} aria-hidden /> : <Copy size={12} aria-hidden />}
      </button>
      <span role="status" className={state === 'failed' ? 'text-[11px] text-risk-medium' : 'sr-only'}>{message}</span>
    </span>
  )
}

function Meta({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-1.5">
      <span className="text-text-secondary">{label}</span>
      {children}
    </div>
  )
}

function ImageHeader({ image }: { image: ImageDetail }) {
  return (
    <div className="flex flex-col gap-2 text-xs">
      <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5">
        <Meta label="Теги">
          {image.tags.length === 0
            ? <span className="text-text-secondary">нет</span>
            : <span className="flex flex-wrap gap-1">{image.tags.map((t) => <span key={t} className="rounded border border-border px-1.5 py-0.5 font-mono text-[11px] text-text">{t}</span>)}</span>}
        </Meta>
        <Meta label="Digest"><DigestCopy short={image.digest_short} full={image.digest} /></Meta>
        <Meta label="Платформа"><span className="font-mono text-text">{image.platform ?? '—'}</span></Meta>
        <Meta label="Размер"><span className="font-mono tabular-nums text-text">{megabytes(image.size)}</span></Meta>
        <Meta label="Отправлен"><span className="font-mono tabular-nums text-text">{date(image.pushed_at)}</span></Meta>
      </div>
      <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5">
        <Meta label="Скан">
          <span className={cn(image.scan_status === 'error' ? 'text-risk-high' : 'text-text')}>
            {[image.scanner, image.scanned_at ? date(image.scanned_at) : null, SCAN_STATUS_LABELS[image.scan_status] ?? image.scan_status].filter(Boolean).join(' · ')}
          </span>
        </Meta>
        <TrivyCounts trivy={image.trivy} />
        <Meta label="Риск">
          {image.risk_max !== null && image.level !== null
            ? <RiskBadge score={image.risk_max} level={image.level} />
            : <span className="text-text-secondary" title={NO_RISK_TITLE}>—</span>}
        </Meta>
      </div>
      {image.sync_error && (
        <div className="text-risk-medium" role="status">Не обновлён в последней синхронизации: {image.sync_error}</div>
      )}
    </div>
  )
}

/**
 * Страница образа: шапка с данными Harbor и оценкой Trivy, ниже — находки образа с фасетами,
 * поиском и дровером расчёта риска. Фильтры, поиск и сортировка — в адресе (без новой записи истории).
 */
export function ImagePage({ id }: { id: number }) {
  const params = useSearchParams()
  const { search, navigate } = useRouter()
  const [filters, setFilters] = useState<ImageVulnFilters>(() => {
    const fixed = params.get('fixed')
    return {
      severity: listFrom(params, 'severity', TRIVY_SEVERITIES),
      level: listFrom(params, 'level', IMAGE_LEVELS),
      fixed: fixed === 'yes' || fixed === 'no' ? fixed : undefined,
    }
  })
  const [sort, setSort] = useState<ImageVulnSort>(() => {
    const s = params.get('sort') as ImageVulnSort | null
    return s && SORTS.includes(s) ? s : DEFAULT_SORT
  })
  const [searchInput, setSearchInput] = useState(() => params.get('q') ?? '')
  const q = useDebouncedValue(searchInput, 250)
  const [selectedIndex, setSelectedIndex] = useState(0)
  const [openKey, setOpenKey] = useState<string | null>(null)
  const searchRef = useRef<HTMLInputElement>(null)
  const filtersPanel = useFiltersPanel('vm-image-vulns')

  const image = useImage(id)
  const vulnQuery = useMemo(() => ({ ...filters, q: q || undefined, sort }), [filters, q, sort])
  const query = useImageVulns(id, vulnQuery)
  const items = useMemo(() => query.data?.pages.flatMap((p) => p.items) ?? [], [query.data])
  const facets = query.data?.pages[0]?.facets ?? undefined
  const total = query.data?.pages[0]?.total ?? 0

  // Отбор — в адрес без новой записи истории; сортировка по умолчанию не пишется.
  useEffect(() => {
    const next = buildQuery({ ...vulnQuery, sort: sort === DEFAULT_SORT ? undefined : sort })
    if (next !== search) navigate(`/vm/images/${id}${next}`, { replace: true })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vulnQuery])
  useEffect(() => { setSelectedIndex(0); setOpenKey(null) }, [vulnQuery, id])

  const selected: ImageVulnItem | null = items[selectedIndex] ?? null
  const openItem = openKey === null ? null : items.find((i) => vulnKey(i) === openKey) ?? null

  function toggle<K extends keyof ImageVulnFilters>(key: K, value: ImageVulnFilters[K]) {
    setFilters((prev) => ({ ...prev, [key]: value }))
  }
  function clearAll() {
    setFilters({})
    setSearchInput('')
  }

  // Что выбрано, пока панель свёрнута: фильтр из ссылки не должен действовать незаметно.
  const chips: FilterChip[] = [
    ...valueChips('Trivy', filters.severity, (s) => TRIVY_SEVERITY_LABELS[s], (v) => toggle('severity', v)),
    ...valueChips('Риск', filters.level, (l) => IMAGE_LEVEL_LABELS[l], (v) => toggle('level', v)),
    ...(filters.fixed ? [{ label: filters.fixed === 'yes' ? 'Исправление: есть' : 'Исправление: нет', clear: () => toggle('fixed', undefined) }] : []),
  ]

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        if (openKey !== null) return setOpenKey(null)
        if (document.activeElement instanceof HTMLElement) document.activeElement.blur()
        return
      }
      if (isTypingTarget(e.target)) return
      // Enter на кнопке или ссылке нажимает её (копирование digest, экспорт), а не открывает карточку расчёта.
      if (e.key === 'Enter' && e.target instanceof HTMLElement && (e.target.tagName === 'BUTTON' || e.target.tagName === 'A')) return
      if (e.key === '/') { e.preventDefault(); searchRef.current?.focus(); return }
      if (e.key === 'j') { e.preventDefault(); setSelectedIndex((i) => Math.min(items.length - 1, i + 1)); return }
      if (e.key === 'k') { e.preventDefault(); setSelectedIndex((i) => Math.max(0, i - 1)); return }
      if (e.key === 'Enter' && selected) { e.preventDefault(); setOpenKey(vulnKey(selected)) }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [items.length, selected, openKey])

  const hasFilters = chips.length > 0 || q !== ''
  const imageError = image.error instanceof ApiRequestError ? image.error.message : image.isError ? 'Не удалось загрузить образ' : null
  const errorMessage = query.error instanceof ApiRequestError ? query.error.message : query.isError ? 'Не удалось загрузить находки образа' : null
  const crumbs = (
    <nav aria-label="Навигация" className="flex min-w-0 items-center gap-1.5 text-xs text-text-secondary">
      <Link to="/vm/images" className="shrink-0 underline underline-offset-2 hover:text-text">Образы контейнеров</Link>
      <span aria-hidden>›</span>
      <span className="min-w-0 truncate font-mono text-text" aria-current="page">{image.data?.name ?? `образ #${id}`}</span>
    </nav>
  )

  if (imageError || !image.data) {
    return (
      <div className="flex h-full min-h-0 flex-col">
        <header className="shrink-0 border-b border-grid bg-surface px-4 py-2.5">{crumbs}</header>
        {imageError ? <div className="p-6"><ErrorState message={imageError} onRetry={() => image.refetch()} /></div> : <FullPageSpinner />}
      </div>
    )
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex shrink-0 flex-col gap-2.5 border-b border-grid bg-surface px-4 py-2.5">
        {crumbs}
        <h1 className="truncate font-mono text-sm font-semibold text-text" title={image.data.name}>{image.data.name}</h1>
        <ImageHeader image={image.data} />
      </header>

      <div className="flex shrink-0 flex-wrap items-center gap-3 border-b border-grid bg-surface px-4 py-2">
        <FiltersButton open={filtersPanel.open} onToggle={filtersPanel.toggle} count={chips.length} />
        {/* Выгрузка — все находки образа: ручка фильтрует по образу, а не по находкам. */}
        <ExportButton href={exportHref('/api/vm/images/export', { image_id: id })} total={image.data.trivy.total} disabled={query.isLoading} title="Выгрузить все находки образа" />
        <div className="relative max-w-sm flex-1">
          <Search size={14} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-text-secondary" aria-hidden />
          <input
            ref={searchRef}
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder="CVE или пакет… (/)"
            aria-label="Поиск по CVE и пакету"
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
      </div>

      <div className="flex min-h-0 flex-1">
        {filtersPanel.open && <ImageVulnsFacetPanel facets={facets} filters={filters} onToggle={toggle} total={total} />}
        <div className="min-w-0 flex-1 bg-app-bg">
          {query.isLoading && <FullPageSpinner />}
          {errorMessage && <div className="p-6"><ErrorState message={errorMessage} onRetry={() => query.refetch()} /></div>}
          {!query.isLoading && !errorMessage && items.length === 0 && (
            <div className="p-6">
              {hasFilters ? (
                <EmptyState icon={FilterX} title="Ничего не найдено" description="Ни одна находка не подходит под фильтры. Сбросьте их или измените запрос." />
              ) : (
                <EmptyState
                  icon={ShieldCheck}
                  title="Находок нет"
                  description={image.data.scan_status === 'success'
                    ? 'В отчёте Trivy для этого образа нет уязвимостей.'
                    : `Отчёта Trivy по образу пока нет (скан: ${SCAN_STATUS_LABELS[image.data.scan_status]}).`}
                />
              )}
            </div>
          )}
          {!query.isLoading && !errorMessage && items.length > 0 && (
            <ImageVulnsTable
              items={items}
              rowKey={vulnKey}
              selectedIndex={selectedIndex}
              sort={sort}
              onSort={setSort}
              onSelectIndex={setSelectedIndex}
              onOpen={(i) => setOpenKey(vulnKey(items[i]))}
              onReachEnd={() => {
                if (query.hasNextPage && !query.isFetchingNextPage) query.fetchNextPage()
              }}
            />
          )}
        </div>
      </div>

      <ImageRiskDrawer imageId={id} item={openItem} onClose={() => setOpenKey(null)} />
    </div>
  )
}
