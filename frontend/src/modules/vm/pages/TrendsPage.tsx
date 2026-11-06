import { useEffect, useState } from 'react'
import { Button } from '@/components/ui/Button'
import { Spinner } from '@/components/ui/Spinner'
import { ErrorState } from '@/components/ui/ErrorState'
import { Link, useRouter } from '@/lib/router'
import { FIELD } from '@/platform/collector/ui'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'
import { ResizableHeader } from '@/platform/table/ResizableHeader'
import { DEFAULT_TREND_SCOPE, reasons, trendPeriods, useTrends, when, type TrendPeriod, type TrendScope } from '../api/trends'
import { TrendDrawer } from './trends/TrendDrawer'
import { publicationUrl } from './trends/publicationUrl'

const COLUMNS: ColumnDef[] = [
  { key: 'identifier', label: 'Уязвимость', width: 180 },
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
  const [view, setView] = useState('mentions')
  const [period, setPeriod] = useState<TrendPeriod>('7d')
  const [dateFrom, setDateFrom] = useState(() => localDate(6))
  const [dateTo, setDateTo] = useState(() => localDate())
  const [query, setQuery] = useState('')
  const [filters, setFilters] = useState(false)
  const [region, setRegion] = useState('')
  const [language, setLanguage] = useState('')
  const [reason, setReason] = useState('')
  const [publisher, setPublisher] = useState('')
  const [status, setStatus] = useState('')
  const [sort, setSort] = useState('date')
  const [offset, setOffset] = useState(0)
  const scope: TrendScope = { period, tz: DEFAULT_TREND_SCOPE.tz, ...(period === 'custom' ? { date_from: dateFrom, date_to: dateTo } : {}) }
  const validPeriod = period !== 'custom' || Boolean(dateFrom && dateTo && dateFrom <= dateTo)
  const data = useTrends({ ...scope, view, q: query, region, language, reason, publisher, status, sort, offset, limit: 50 }, validPeriod)
  const columns = useColumnWidths('vm-trends-columns', COLUMNS)
  function change(action: () => void) { setOffset(0); action() }
  return <div className="flex h-full min-h-0 flex-col text-text">
    <div className="space-y-3 border-b border-grid p-5">
      <div className="flex flex-wrap items-center justify-between gap-3"><h1 className="text-xl font-semibold">Обсуждения и тренды CVE</h1><Link to="/settings/vm#trends" className="text-sm underline">Настройки сборщика</Link></div>
      <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Представление публикаций">
        {VIEWS.map(({ value, label }) => <Button key={value} variant={view === value ? 'primary' : 'secondary'} aria-pressed={view === value} onClick={() => change(() => setView(value))}>{label}</Button>)}
      </div>
      <p className="text-sm text-text-secondary">{VIEWS.find(item => item.value === view)?.description}</p>
      <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Период публикаций">
        <span className="text-sm text-text-secondary">Период:</span>
        {trendPeriods.map(({ value, label }) => <Button key={value} variant={period === value ? 'primary' : 'secondary'} aria-pressed={period === value} onClick={() => change(() => setPeriod(value))}>{label}</Button>)}
      </div>
      {period === 'custom' && <div className="flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-2 text-sm">С <input className={FIELD} type="date" aria-label="Начало периода" max={dateTo || undefined} value={dateFrom} onChange={e => change(() => setDateFrom(e.target.value))} /></label>
        <label className="flex items-center gap-2 text-sm">По <input className={FIELD} type="date" aria-label="Конец периода включительно" min={dateFrom || undefined} value={dateTo} onChange={e => change(() => setDateTo(e.target.value))} /></label>
        {!validPeriod && <p role="alert" className="text-sm text-danger">Укажите обе даты: начало периода должно быть не позже конца.</p>}
      </div>}
      <p className="text-xs text-text-secondary">{period === 'all' ? 'Архив за всё время; эти записи не обязательно обсуждают сейчас.' : 'Отбор по исходной дате публикации, а не году CVE или дате загрузки.'} Часовой пояс: {scope.tz}. {period === 'custom' && 'Обе даты включены.'}</p>
      <div className="flex flex-wrap items-center gap-2">
        <input aria-label="Поиск CVE или продукта" className={FIELD} style={{ width: 280 }} placeholder="CVE, продукт или заголовок" value={query} onChange={e => change(() => setQuery(e.target.value))} />
        <Button aria-expanded={filters} onClick={() => setFilters(!filters)}>Фильтры</Button>
        <Button disabled={!validPeriod || data.isFetching} onClick={() => data.refetch()}>Обновить</Button>
        <select className={FIELD} style={{ width: 240 }} aria-label="Сортировка" value={sort} onChange={e => change(() => setSort(e.target.value))}><option value="priority">По приоритету</option><option value="date">По дате публикации</option><option value="impact">По числу объектов</option><option value="identifier">По идентификатору</option></select>
      </div>
      {filters && <div className="grid gap-3 md:grid-cols-3">
        <select aria-label="Регион" className={FIELD} value={region} onChange={e => change(() => setRegion(e.target.value))}><option value="">Все регионы</option><option value="RU">Россия</option><option value="EU">Европа</option><option value="CN">Китай</option><option value="GLOBAL">Международные</option></select>
        <select aria-label="Основание тренда" className={FIELD} value={reason} onChange={e => change(() => setReason(e.target.value))}><option value="">Все основания</option>{Object.entries(reasons).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select>
        <input aria-label="Язык" className={FIELD} placeholder="Язык, например zh" value={language} onChange={e => change(() => setLanguage(e.target.value))} />
        <input aria-label="Издатель" className={FIELD} placeholder="Издатель, например cert-fr" value={publisher} onChange={e => change(() => setPublisher(e.target.value))} />
        <select className={FIELD} aria-label="Статус" value={status} onChange={e => change(() => setStatus(e.target.value))}><option value="">Все статусы</option><option value="new">Новые</option><option value="verified">Проверенные</option><option value="rejected">Отклонённые</option></select>
      </div>}
      <p className="text-xs text-text-secondary">Получено из сборщика — {when(data.data?.received_at)} · {validPeriod ? `Найдено ${data.data?.total ?? 0}` : 'Период не задан'}</p>
    </div>
    {data.isLoading && <Spinner />}
    {data.error && <ErrorState message={data.error.message} onRetry={() => data.refetch()} />}
    <div className="min-h-0 flex-1 overflow-auto" data-col-resize-root>
      <div className="sticky top-0 z-10 grid border-b border-grid bg-surface text-xs text-text-secondary" style={columns.gridStyle}><ResizableHeader as="div" cols={columns} className="px-3 py-3" /></div>
      {validPeriod && data.data?.items.map(item => {
        const url = publicationUrl(item.source_url, item.id)
        return <div key={item.id} className="grid w-full cursor-pointer items-center border-b border-grid text-left text-sm hover:bg-row-hover focus-within:bg-row-selected" style={columns.gridStyle} onClick={() => setSelected(item.id)}>
        <button type="button" className="self-stretch px-3 py-3 text-left font-mono focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent" aria-label={`Открыть карточку ${item.id.startsWith('signal-') ? item.title : item.id}`}>{item.id.startsWith('signal-') ? 'Без CVE' : item.id}</button>
        <span className="min-w-0 break-words px-3 py-3">{item.title}<span className="mt-1 block text-xs text-text-secondary">Публикаций: {item.publication_count} · Новостей: {item.news_count} · Издателей: {item.publisher_count}</span><span className="block text-xs text-text-secondary">{item.status === 'verified' ? 'Проверен аналитиком' : item.status === 'rejected' ? 'Отклонён аналитиком' : 'Новый'}</span></span>
        <span className="break-words px-3 py-3 text-text-secondary" title="Источник показанной публикации">{url ? <a href={url} target="_blank" rel="noopener noreferrer" className="underline hover:text-text-primary" title="Открыть публикацию в новой вкладке" onClick={event => event.stopPropagation()}>{item.source_name || 'Публикация'}</a> : item.source_name || '—'}</span>
        <span className="px-3 py-3">{reasons[item.reason] ?? item.reason}<span className="block text-xs text-text-secondary">Независимых материалов: {item.independent_sources}</span></span>
        <span className="px-3 py-3">{item.hosts} хостов · {item.images} образов</span>
        <span className="px-3 py-3 text-xs">{when(item.last_event_at)}</span>
      </div>})}
      {validPeriod && data.data?.total === 0 && <div className="space-y-2 p-8 text-sm text-text-secondary"><p>{view === 'matched' ? 'За выбранный период нет трендов с точными совпадениями в локальных данных. Откройте «Обсуждаемые CVE» и проверьте актуальность сканов.' : view === 'all' ? 'За выбранный период нет публикаций, подтверждающих критерии тренда. Другие упоминания доступны в «Обсуждаемые CVE».' : 'За выбранный период публикаций по этим условиям нет.'}</p><p>Измените период или фильтры. Если ожидались свежие сообщения, проверьте получение источников в настройках сборщика.</p></div>}
    </div>
    <div className="flex items-center gap-3 border-t border-grid p-3"><Button disabled={!validPeriod || offset === 0} onClick={() => setOffset(Math.max(0, offset - 50))}>Назад</Button><span className="text-sm">Страница {Math.floor(offset / 50) + 1}</span><Button disabled={!validPeriod || offset + 50 >= (data.data?.total ?? 0)} onClick={() => setOffset(offset + 50)}>Далее</Button></div>
    {selected && validPeriod && <TrendDrawer id={selected} scope={scope} close={() => setSelected('')} />}
  </div>
}
