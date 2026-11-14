import { useEffect, useState } from 'react'
import { Search } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { Spinner } from '@/components/ui/Spinner'
import { Link, useRouter } from '@/lib/router'
import { CVE_BASE, useCve, useCveSearch, type CveDetail } from '../api/cve'
import { SeverityBadge } from './trends/SeverityBadge'
import { ReadingAssistant } from './trends/ReadingAssistant'
import { CveRisk } from './cve/CveRisk'
import { AdvisoryMetadata } from './cve/AdvisoryMetadata'
import { CveImages } from './cve/CveImages'
import { CveMatches } from './cve/CveMatches'

const normalize = (value: string) => value.trim().toUpperCase().startsWith('GHSA') ? 'GHSA'+value.trim().slice(4).toLowerCase() : value.trim().toUpperCase()
const percent = (value: number) => new Intl.NumberFormat('ru-RU', { style: 'percent', minimumFractionDigits: 2, maximumFractionDigits: 2 }).format(value)
const date = (value: string | null) => value ? new Date(value).toLocaleDateString('ru-RU') : 'Нет данных'

function Card({ data }: { data: CveDetail }) {
  return <div className="space-y-4">
    <section className="space-y-4 rounded border border-grid bg-surface p-4">
      <div className="flex flex-wrap items-start justify-between gap-3"><h2 className="font-mono text-lg font-semibold">{data.id}</h2><a className="text-xs text-primary hover:underline" href={data.primary_url} target="_blank" rel="noopener noreferrer">{data.id.startsWith('GHSA-') ? 'Карточка GitHub' : 'Карточка CVE.org'}</a></div>
      <div className="grid gap-4 rounded border border-grid bg-app-bg p-3 sm:grid-cols-3">
        <div><p className="mb-1 text-xs text-text-secondary">Критичность уязвимости</p><SeverityBadge value={data} /></div>
        <div><p className="mb-1 text-xs text-text-secondary">Вероятность эксплуатации · EPSS</p><p className="font-semibold">{data.epss === null ? 'Нет данных' : percent(data.epss)}</p><p className="mt-1 text-[11px] text-text-secondary">Прогноз на 30 дней, не вероятность атаки конкретного хоста.</p></div>
        <div><p className="mb-1 text-xs text-text-secondary">Известная эксплуатация</p><p className={`text-sm font-semibold ${data.known_exploited ? 'text-risk-critical' : ''}`}>{data.known_exploited === true ? 'Подтверждена' : data.known_exploited === false ? 'Не отмечена в загруженных данных' : 'Нет данных'}</p></div>
      </div>
      <AdvisoryMetadata data={data} /><div><h3 className="mb-2 text-sm font-semibold">Описание</h3>{data.description ? <ReadingAssistant key={data.id} cardId={data.id} originalText={data.description} apiBase={CVE_BASE} /> : <p className="text-xs text-text-secondary">Описание отсутствует в загруженных базах. Обновите справочники NVD и GitHub Advisory Database.</p>}<p className="mt-2 text-[11px] text-text-secondary">{data.description_source && `Описание: ${data.description_source} · `}Опубликована: {date(data.published)} · Обновлена: {date(data.modified)}</p></div>
      <details className="text-xs"><summary className="cursor-pointer text-text-secondary">Источники и признаки эксплуатации</summary><div className="mt-3 space-y-3">
        <ul className="space-y-1">{data.sources.map(s => <li key={s.id}>{s.url ? <a className="text-primary hover:underline" href={s.url} target="_blank" rel="noopener noreferrer">{s.name}</a> : s.name}<span className="text-text-secondary"> · Загружено: {date(s.loaded_at)}</span></li>)}</ul>
        <p>ExploitDB: {data.exploits.length} · Metasploit: {data.msf_modules.length} · Образов Harbor с CVE: {data.images_total}</p>
        {data.exploits.length > 0 && <div className="flex flex-wrap gap-3">{data.exploits.map(e => <a key={e.id} href={e.url} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">EDB-{e.id} · {e.type}</a>)}</div>}
        {data.msf_modules.length > 0 && <ul className="space-y-1 break-all font-mono">{data.msf_modules.map(m => <li key={m.name}>{m.name}</li>)}</ul>}
        {data.attack.length > 0 && <p>ATT&CK: {data.attack.join(', ')}</p>}
      </div></details>
    </section>
    {!data.withdrawn && <CveRisk data={data} />}<CveMatches key={data.id} data={data} /><CveImages key={data.id+'-images'} data={data} />
  </div>
}

export function CveSearchPage() {
  const { search, navigate } = useRouter()
  const params = new URLSearchParams(search)
  const submitted = params.get('q') ?? params.get('id') ?? ''
  const selected = params.get('id') ?? (/^(?:CVE-\d{4}-\d{4,19}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})$/i.test(submitted) ? normalize(submitted) : '')
  const [input, setInput] = useState(submitted), [error, setError] = useState('')
  useEffect(() => { setInput(submitted); setError('') }, [submitted])
  const rawOffset = Number(params.get('offset'))
  const offset = Number.isSafeInteger(rawOffset) ? Math.max(0, rawOffset) : 0
  const results = useCveSearch(submitted, offset), detail = useCve(selected)
  const base = `/vm/cve?q=${encodeURIComponent(submitted)}`
  return <div className="flex h-full min-h-0 flex-col text-text">
    <header className="shrink-0 space-y-2 border-b border-grid bg-surface px-4 py-3"><h1 className="text-sm font-semibold">Поиск уязвимостей</h1>
      <form className="flex flex-wrap items-center gap-2" onSubmit={e => { e.preventDefault(); const q = normalize(input); if (!/^(?:CVE-\d{4}(?:-\d{0,19})?|GHSA(?:-[23456789cfghjmpqrvwx]{0,4}){0,3})$/.test(q)) { setError('Введите CVE, GHSA или начало номера'); return }; setError(''); navigate(`/vm/cve?q=${encodeURIComponent(q)}`) }}>
        <label className="relative min-w-52 max-w-xl flex-1"><span className="sr-only">Номер CVE или GHSA</span><Search size={14} className="absolute top-2.5 left-3 text-text-secondary" aria-hidden /><input className="w-full rounded border border-border bg-app-bg py-2 pr-3 pl-9 font-mono text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" value={input} maxLength={40} onChange={e => setInput(e.target.value)} placeholder="CVE-2026-12345 или GHSA-…" /></label><Button type="submit" variant="primary">Найти</Button>
      </form>{error && <p role="alert" className="text-xs text-kind-1">{error}</p>}<p className="text-xs text-text-secondary">Поиск по загруженным справочникам и локальным данным. Уязвимость можно найти, даже если на наших хостах её нет.</p>
    </header>
    {!submitted ? <div className="p-6 text-sm text-text-secondary">Введите номер CVE, GHSA или его начало. Описание, критичность, риск и локальные совпадения появятся в карточке.</div> : <div className="grid min-h-0 flex-1 overflow-auto lg:grid-cols-[280px_minmax(0,1fr)]">
      <aside className="border-b border-grid bg-surface p-3 lg:overflow-auto lg:border-r lg:border-b-0" aria-label="Результаты поиска уязвимостей">
        {results.isPending && <Spinner />}{results.error && <ErrorState message={results.error.message} onRetry={() => results.refetch()} />}
        {results.data?.items.length === 0 && <p className="text-xs text-text-secondary">В загруженных базах совпадений нет. Проверьте номер или <Link className="text-primary hover:underline" to="/settings/vm#references">обновите справочники</Link>.</p>}
        <div className="space-y-1">{results.data?.items.map(row => <Link key={row.id} to={`${base}&offset=${offset}&id=${encodeURIComponent(row.id)}`} aria-current={row.id === selected ? 'page' : undefined} className={`block rounded border p-3 text-xs ${row.id === selected ? 'border-primary bg-row-selected' : 'border-transparent hover:bg-row-hover'}`}><span className="block font-mono font-semibold">{row.id}</span><span className="mt-1 block text-text-secondary">{row.sources.join(' · ')}</span></Link>)}</div>
        {(offset > 0 || results.data?.has_more) && <div className="mt-3 flex justify-between gap-2"><Button disabled={offset === 0} onClick={() => navigate(`${base}&offset=${Math.max(0,offset-20)}`)}>Назад</Button><Button disabled={!results.data?.has_more} onClick={() => navigate(`${base}&offset=${offset+20}`)}>Далее</Button></div>}
      </aside>
      <main className="min-w-0 p-4 lg:overflow-auto">{selected ? <>{detail.isPending && <Spinner />}{detail.error && <ErrorState message={detail.error.message} onRetry={() => detail.refetch()} />}{detail.data && <Card key={detail.data.id} data={detail.data} />}</> : <p className="text-sm text-text-secondary">Выберите уязвимость из результатов поиска.</p>}</main>
    </div>}
  </div>
}
