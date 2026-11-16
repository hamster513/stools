import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import { MonitoringStatus } from './trends/MonitoringStatus'
import { useEffect, useState } from 'react'
import { Button } from '@/components/ui/Button'
import { Spinner } from '@/components/ui/Spinner'
import { ErrorState } from '@/components/ui/ErrorState'
import { Link, useRouter } from '@/lib/router'
import { Search, RefreshCw, Settings, FilterX } from 'lucide-react'
import { FiltersButton, FilterChips, type FilterChip } from '@/platform/filters/FiltersBar'
import { useFiltersPanel } from '@/platform/filters/useFiltersPanel'
import { Section } from './vulns/FacetPanel'
const FIELD = 'w-full rounded border border-border bg-app-bg px-2 py-1.5 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'
import { ResizableHeader } from '@/platform/table/ResizableHeader'
import { DEFAULT_TREND_SCOPE, reasons, trendPeriods, useTrends, when, type TrendPeriod, type TrendScope } from '../api/trends'
import { SeverityBadge } from './trends/SeverityBadge'
import { TrendDrawer } from './trends/TrendDrawer'
import { publicationUrl } from './trends/publicationUrl'

const COLUMNS: ColumnDef[] = [
  { key: 'identifier', label: 'Уязвимость', width: 180 },
  { key: 'severity', label: 'Критичность', width: 160 },
  { key: 'title', label: 'Публикации', width: 380, flex: true },
  { key: 'source', label: 'Источник', width: 190 },
  { key: 'reason', label: 'Основание за период', width: 250 },
  { key: 'matches', label: 'У нас', width: 160 },
  { key: 'date', label: 'Последняя публикация', width: 180 },
]
const VIEWS = [
  { value: 'mentions', label: 'Обсуждаемые CVE', description: 'CVE и GHSA, упомянутые в публикациях за выбранный период. Упоминание само по себе не подтверждает эксплуатацию или тренд.' },
  { value: 'all', label: 'Трендовые CVE', description: 'За выбранный период есть подтверждённая эксплуатация или не менее двух независимых материалов. Наличие у нас не требуется.' },
  { value: 'matched', label: 'Найдено у нас', description: 'Трендовые CVE за выбранный период с точными совпадениями в загруженных данных MaxPatrol VM и Harbor.' },
  { value: 'review', label: 'Ранние сигналы / На проверку', description: 'Публикации за выбранный период для проверки аналитиком, в том числе ранние сигналы без CVE.' },
  { value: 'archive', label: 'Все собранные публикации', description: 'Полная история сбора: включает обычные новости, исключённые материалы и записи без даты. Здесь можно проверить фильтрацию и вернуть публикацию в анализ; наличие в этом списке не означает угрозу.' },
]
function localDate(daysAgo = 0) {
  const date = new Date()
  date.setDate(date.getDate() - daysAgo)
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`
}

export function TrendsPage() {
  const { search } = useRouter()
  const [selected, setSelected] = useState(() => new URLSearchParams(search).get('id') ?? '')
  useEffect(() => { setSelected(new URLSearchParams(search).get('id') ?? '') }, [search])
  const [view, setView] = useState(() => VIEWS.find(v => v.value === new URLSearchParams(search).get('view'))?.value ?? 'mentions')
  const [period, setPeriod] = useState<TrendPeriod>(() => trendPeriods.find(p => p.value === new URLSearchParams(search).get('period'))?.value ?? '7d')
  const [dateFrom, setDateFrom] = useState(() => localDate(6))
  const [dateTo, setDateTo] = useState(() => localDate())
  const [fromArchive, setFromArchive] = useState(() => new URLSearchParams(search).get('from_archive') === 'true')
  const [query, setQuery] = useState('')
  const filtersPanel = useFiltersPanel('vm-trends')
  const [region, setRegion] = useState('')
  const [language, setLanguage] = useState('')
  const [reason, setReason] = useState('')
  const [publisher, setPublisher] = useState('')
  const [status, setStatus] = useState('')
  const sources = useQuery({ queryKey: ['vm-trends', 'publication-sources'], queryFn: () => api.get<{ items: { id: string; name: string }[] }>('/api/vm/trends/publication-sources') })
  const [sourceId, setSourceId] = useState('')
  const [product, setProduct] = useState('')
  const [pocState, setPocState] = useState('')
  const [sort, setSort] = useState('date')
  const [offset, setOffset] = useState(0)
  const scope: TrendScope = { period, tz: DEFAULT_TREND_SCOPE.tz, ...(period === 'custom' ? { date_from: dateFrom, date_to: dateTo } : {}) }
  const validPeriod = period !== 'custom' || Boolean(dateFrom && dateTo && dateFrom <= dateTo)
  const data = useTrends({ ...scope, view, from_archive: fromArchive, q: query, region, language, reason, publisher, status, source_id: sourceId, product, poc_state: pocState, sort, offset, limit: 50 }, validPeriod)
  const columns = useColumnWidths('vm-trends-columns', COLUMNS)
  useEffect(() => {
    const params = new URLSearchParams(search)
    const nextView = VIEWS.find(v => v.value === params.get('view'))
    const nextPeriod = trendPeriods.find(p => p.value === params.get('period'))
    if (nextView) setView(nextView.value)
    if (nextPeriod) setPeriod(nextPeriod.value)
    if (params.has('from_archive')) setFromArchive(params.get('from_archive') === 'true')
    setOffset(0)
  }, [search])
  function change(action: () => void) { setOffset(0); action() }
  const chips: FilterChip[] = [
    { label: fromArchive ? 'Только из ZIP' : '', clear: () => change(() => setFromArchive(false)) },
    { label: period !== 'all' ? `Период: ${period === 'custom' ? `${dateFrom} — ${dateTo}` : trendPeriods.find(p => p.value === period)?.label}` : '', clear: () => change(() => setPeriod('all')) },
    { label: sort !== 'date' ? `Сортировка: ${({ priority: 'приоритет', impact: 'число объектов', identifier: 'идентификатор' } as Record<string, string>)[sort] ?? sort}` : '', clear: () => change(() => setSort('date')) },
    { label: sourceId ? `Источник: ${sources.data?.items.find(s => s.id === sourceId)?.name ?? sourceId}` : '', clear: () => change(() => setSourceId('')) },
    ...[
      [product, 'Продукт', setProduct], [pocState, 'PoC', setPocState], [region, 'Регион', setRegion],
      [reason, 'Основание', setReason], [language, 'Язык', setLanguage], [publisher, 'Издатель', setPublisher], [status, 'Статус', setStatus],
    ].map(([value, label, setter]) => ({ label: value ? `${label}: ${reasons[value as string] ?? value}` : '', clear: () => change(() => (setter as (v: string) => void)('')) })),
  ].filter(chip => chip.label)
  function clearFilters() { change(() => { setQuery(''); chips.forEach(chip => chip.clear()); setPeriod('7d'); setSort('date') }) }
  return <div className="flex h-full min-h-0 flex-col text-text">
    <header className="flex shrink-0 flex-wrap items-center gap-3 border-b border-grid bg-surface px-4 py-2.5">
      <h1 className="text-sm font-semibold">Обсуждения и тренды CVE</h1>
      <FiltersButton open={filtersPanel.open} onToggle={filtersPanel.toggle} count={chips.length} />
      <div className="relative min-w-40 max-w-sm flex-1">
        <Search size={14} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-text-secondary" aria-hidden />
        <input aria-label="Поиск CVE или продукта" className={`${FIELD} pl-8`} placeholder="CVE, продукт или заголовок…" value={query} onChange={e => change(() => setQuery(e.target.value))} />
      </div>
      {(chips.length > 0 || query) && <button type="button" onClick={clearFilters} className="flex items-center gap-1.5 rounded px-2 py-1 text-xs text-text-secondary hover:bg-row-hover hover:text-text"><FilterX size={13} aria-hidden />Сбросить</button>}
      <span className="font-mono text-xs tabular-nums text-text-secondary">{validPeriod ? data.data?.total?.toLocaleString('ru-RU') ?? '…' : '—'}</span>
      <button type="button" disabled={!validPeriod || data.isFetching} onClick={() => data.refetch()} className="rounded p-1.5 text-text-secondary hover:bg-row-hover hover:text-text disabled:opacity-40" aria-label="Обновить" title="Обновить"><RefreshCw size={14} aria-hidden /></button>
      <Link to="/settings/vm#trends" className="ml-auto flex items-center gap-1.5 rounded px-2 py-1 text-xs text-text-secondary hover:bg-row-hover hover:text-text"><Settings size={13} aria-hidden />Настройки мониторинга</Link>
      {!filtersPanel.open && <FilterChips chips={chips} />}
    </header>
    <div className="shrink-0 space-y-2 border-b border-grid bg-surface px-4 py-2">
      <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Представление публикаций">
        {VIEWS.map(({ value, label }) => <Button className="px-2 py-1 text-xs" key={value} variant={view === value ? 'primary' : 'ghost'} aria-pressed={view === value} onClick={() => change(() => { setView(value); if (value === 'archive') setPeriod('all') })}>{label}</Button>)}
      </div>
      <p className="text-xs text-text-secondary">{VIEWS.find(item => item.value === view)?.description}</p>
      <MonitoringStatus />
      <p role="status" aria-live="polite" className="text-xs text-text-secondary">
        {!validPeriod ? 'Период не задан' : !data.data
          ? data.isError ? 'Не удалось загрузить список публикаций' : 'Загрузка публикаций…'
          : data.isPlaceholderData ? 'Обновление списка… Пока показан предыдущий результат.'
          : <>Последнее получение публикаций — {data.data.received_at ? when(data.data.received_at) : 'Дата получения не указана'} · Найдено {data.data.total}{data.isFetching && ' · Обновление…'}</>}
      </p>
    </div>
    {data.isLoading && <Spinner />}
    {data.error && <ErrorState message={data.error.message} onRetry={() => data.refetch()} />}
    <div className="flex min-h-0 flex-1">
      {filtersPanel.open && <aside aria-label="Фильтры публикаций" className="w-60 shrink-0 overflow-y-auto border-r border-grid bg-surface">
        <Section title="Период"><select className={FIELD} aria-label="Период публикаций" value={period} onChange={e => change(() => setPeriod(e.target.value as TrendPeriod))}>{trendPeriods.map(({ value, label }) => <option key={value} value={value}>{label}</option>)}</select>
      {period === 'custom' && <div className="mt-2 space-y-2">
            <label className="flex flex-col gap-1 text-xs">С <input className={FIELD} type="date" aria-label="Начало периода" max={dateTo || undefined} value={dateFrom} onChange={e => change(() => setDateFrom(e.target.value))} /></label>
            <label className="flex flex-col gap-1 text-xs">По <input className={FIELD} type="date" aria-label="Конец периода включительно" min={dateFrom || undefined} value={dateTo} onChange={e => change(() => setDateTo(e.target.value))} /></label>
            {!validPeriod && <p role="alert" className="text-xs text-kind-1">Укажите обе даты: начало должно быть не позже конца.</p>}
          </div>}
          <p className="mt-2 text-[11px] text-text-secondary">{period === 'all' ? 'Вся история публикаций, включая старые сообщения.' : 'Отбор по исходной дате публикации.'} Часовой пояс: {scope.tz}.{period === 'custom' && ' Обе даты включены.'}</p>
        </Section>
        <Section title="Сортировка"><select className={FIELD} aria-label="Сортировка" value={sort} onChange={e => change(() => setSort(e.target.value))}><option value="priority">По приоритету</option><option value="date">По дате публикации</option><option value="impact">По числу объектов</option><option value="identifier">По идентификатору</option></select></Section>
        <Section title="Получение"><label className="flex items-center gap-2 text-xs"><input type="checkbox" checked={fromArchive} onChange={e => change(() => setFromArchive(e.target.checked))} />Только из ZIP</label></Section>
        <Section title="Источник"><select className={FIELD} aria-label="Источник публикации" value={sourceId} onChange={e => change(() => setSourceId(e.target.value))}><option value="">Все источники</option>{sources.data?.items.map(source => <option key={source.id} value={source.id}>{source.name}</option>)}</select></Section>
        <Section title="Продукт"><input className={FIELD} aria-label="Продукт" placeholder="Продукт из контекста CVE" value={product} onChange={e => change(() => setProduct(e.target.value))} /></Section>
        <Section title="Статус PoC"><select className={FIELD} aria-label="Статус PoC" value={pocState} onChange={e => change(() => setPocState(e.target.value))}><option value="">Любой статус PoC</option><option value="candidate">Кандидат</option><option value="likely">Вероятный</option><option value="confirmed">Подтверждён аналитиком</option><option value="rejected">Отклонён аналитиком</option></select></Section>
        <Section title="Регион"><select aria-label="Регион" className={FIELD} value={region} onChange={e => change(() => setRegion(e.target.value))}><option value="">Все регионы</option><option value="RU">Россия</option><option value="EU">Европа</option><option value="CN">Китай</option><option value="GLOBAL">Международные</option></select></Section>
        <Section title="Основание"><select aria-label="Основание тренда" className={FIELD} value={reason} onChange={e => change(() => setReason(e.target.value))}><option value="">Все основания</option>{Object.entries(reasons).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select></Section>
        <Section title="Язык"><input aria-label="Язык" className={FIELD} placeholder="Язык, например zh" value={language} onChange={e => change(() => setLanguage(e.target.value))} /></Section>
        <Section title="Издатель"><input aria-label="Издатель" className={FIELD} placeholder="Издатель, например cert-fr" value={publisher} onChange={e => change(() => setPublisher(e.target.value))} /></Section>
        <Section title="Статус проверки"><select className={FIELD} aria-label="Статус" value={status} onChange={e => change(() => setStatus(e.target.value))}><option value="">Все статусы</option><option value="new">Новые</option><option value="verified">Проверенные</option><option value="rejected">Отклонённые</option></select></Section>
      </aside>}
    <div className="min-w-0 flex-1 overflow-auto bg-app-bg" aria-busy={data.isFetching} data-col-resize-root>
      <div className="sticky top-0 z-10 grid border-b border-grid bg-surface text-[11px] font-semibold tracking-wide text-text-secondary uppercase" style={columns.gridStyle}><ResizableHeader as="div" cols={columns} className="px-2 py-2" /></div>
      {validPeriod && data.data?.items.map(item => {
        const url = publicationUrl(item.source_url, item.id)
        return <div key={item.id} data-trend-row={item.id} className={`grid w-full cursor-pointer items-center border-b border-grid text-left text-xs hover:bg-row-hover focus-within:bg-row-selected ${selected === item.id ? 'bg-row-selected' : ''}`} style={columns.gridStyle} onClick={() => setSelected(item.id)}>
        <button type="button" aria-expanded={selected === item.id} className="self-stretch px-2 py-2 text-left font-mono focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent" aria-label={`Открыть карточку ${item.id.startsWith('signal-') ? item.title : item.id}`}>{item.id.startsWith('signal-') ? 'Без CVE' : item.id}</button>
        <span className="px-2 py-2"><SeverityBadge value={item} /></span>
        <span className="min-w-0 break-words px-2 py-2"><span className="line-clamp-2" title={item.title}>{item.title}</span><span className="mt-1 block text-[11px] text-text-secondary">Публикаций: {item.publication_count} · Новостей: {item.news_count} · Издателей: {item.publisher_count}</span><span className="block text-[11px] text-text-secondary">{item.status === 'verified' ? 'Проверен аналитиком' : item.status === 'rejected' ? 'Отклонён аналитиком' : 'Новый'}</span></span>
        <span className="break-words px-2 py-2 text-text-secondary" title="Источник показанной публикации">{url ? <a href={url} target="_blank" rel="noopener noreferrer" className="underline hover:text-text-primary" title="Открыть публикацию в новой вкладке" onClick={event => event.stopPropagation()}>{item.source_name || 'Публикация'}</a> : item.source_name || '—'}</span>
        <span className="px-2 py-2">{reasons[item.reason] ?? item.reason}<span className="block text-[11px] text-text-secondary">Независимых материалов: {item.independent_sources}</span></span>
        <span className="px-2 py-2">{item.hosts} хостов · {item.images} образов</span>
        <span className="px-2 py-2 text-xs">{when(item.last_event_at)}</span>
      </div>})}
      {validPeriod && !data.isFetching && !data.isError && data.data?.total === 0 && <div className="space-y-2 p-8 text-xs text-text-secondary"><p>{view === 'matched' ? 'За выбранный период нет трендов с точными совпадениями в локальных данных. Откройте «Обсуждаемые CVE» и проверьте актуальность сканов.' : view === 'all' ? 'За выбранный период нет публикаций, подтверждающих критерии тренда. Другие упоминания доступны в «Обсуждаемые CVE».' : 'За выбранный период публикаций по этим условиям нет.'}</p><p>Измените период или фильтры. Если ожидались свежие сообщения, проверьте получение источников в настройках сборщика.</p></div>}
    </div>
    </div>
    <div className="flex shrink-0 items-center gap-3 border-t border-grid bg-surface px-4 py-2"><Button className="px-2 py-1 text-xs" disabled={!validPeriod || data.isPlaceholderData || data.isLoading || data.isError || offset === 0} onClick={() => setOffset(Math.max(0, offset - 50))}>Назад</Button><span className="text-xs">{data.isPlaceholderData ? 'Обновление…' : `Страница ${Math.floor(offset / 50) + 1}`}</span><Button className="px-2 py-1 text-xs" disabled={!validPeriod || data.isPlaceholderData || data.isLoading || data.isError || offset + 50 >= (data.data?.total ?? 0)} onClick={() => setOffset(offset + 50)}>Далее</Button></div>
    {selected && validPeriod && <TrendDrawer key={selected} id={selected} scope={scope} close={() => setSelected('')} />}
  </div>
}
