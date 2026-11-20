import { useState } from 'react'
import { ArrowRight, FileCode2, Server } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { FIELD } from '@/components/ui/Field'
import { useRouter } from '@/lib/router'
import { ACTION, dateText, useHistory, useSnapshot, type Directive, type Route } from './api'

function Settings({ items }: { items: Directive[] }) {
  return <div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead><tr className="border-b border-border"><th className="p-2">Директива</th><th className="p-2">Значение</th><th className="p-2">Источник</th></tr></thead><tbody>{items.map((s, i) => <tr key={i} className="border-b border-border"><td className="p-2 font-mono">{s.name}</td><td className="max-w-lg break-all p-2 font-mono">{s.value}</td><td className="break-all p-2 text-xs text-text-secondary">{s.file}:{s.line}</td></tr>)}</tbody></table></div>
}

function RouteGraph({ route, hostname, entry }: { route: Route; hostname: string; entry: string }) {
  const box = 'w-64 shrink-0 rounded border border-border bg-panel p-4 text-sm'
  return <div className="overflow-x-auto rounded border border-border p-4" aria-label="Схема маршрута слева направо">
    <div className="flex min-w-max items-center gap-5">
      <div className={box}><p className="mb-2 text-text-secondary">Вход nginx</p><p className="break-all">{entry}</p><p className="mt-2 text-xs text-text-secondary">Внешняя доступность неизвестна</p></div>
      <ArrowRight aria-label="К nginx" className="shrink-0 text-text-secondary" />
      <div className={box}><Server size={18} className="mb-2 text-primary" /><p className="break-all font-medium">{hostname}</p><p className="mt-2 break-all font-mono">{route.match}</p></div>
      <ArrowRight aria-label="К назначению" className="shrink-0 text-text-secondary" />
      <div className="space-y-2">{route.targets.length ? route.targets.map((t, i) => <div key={i} className={box}>
        <p className="text-text-secondary">{t.local ? 'На том же сервере' : 'Backend'}</p>
        <p className="break-all font-medium">{t.dynamic ? 'Динамическая цель' : `${t.host}${t.port !== null ? ':' + t.port : ''}`}</p><p className="mt-1 break-all font-mono text-xs">{t.address}</p>{t.parameters && <p>{t.parameters}</p>}
        <p className="mt-2 text-xs text-text-secondary">Доступность соединения не проверена</p>
      </div>) : <div className={box}><p>{ACTION[route.action]}</p><p className="mt-2 break-all font-mono">{route.destination || 'Нужны дополнительные данные'}</p></div>}</div>
    </div>
  </div>
}

export function SnapshotPage({ id }: { id: number }) {
  const query = useSnapshot(id)
  const { navigate } = useRouter()
  const history = useHistory(query.data?.server_id ?? 0)
  const [tab, setTab] = useState('routes')
  const [siteIndex, setSiteIndex] = useState(0)
  const [routeIndex, setRouteIndex] = useState(0)
  const [search, setSearch] = useState('')
  const [sourceIndex, setSourceIndex] = useState(0)
  if (query.isPending) return <p role="status">Загрузка снимка…</p>
  if (query.error) return <div role="alert"><p>{query.error.message}</p><Button onClick={() => query.refetch()}>Повторить</Button></div>
  const data = query.data, doc = data.document, site = doc.servers[siteIndex] ?? doc.servers[0]
  const route = site?.routes[routeIndex] ?? site?.routes[0]
  const source = doc.sources[sourceIndex] ?? doc.sources[0]
  const needle = search.toLowerCase()
  function showSource(file: string) { setSourceIndex(Math.max(0, doc.sources.findIndex(s => s.path === file))); setSearch(''); setTab('sources') }
  return <div className="space-y-4">
    <Button onClick={() => navigate('/radar')}>← Все серверы</Button>
    <div><h2 className="break-all text-xl font-semibold">{data.hostname}</h2><p className="mt-1 text-sm text-text-secondary">Импорт: {dateText(data.imported_at)}. Время сбора конфигурации неизвестно.</p>
      {data.asset && <p className="text-sm">Совпадение в Assets: {data.asset.name} (#{data.asset.id})</p>}
      {data.asset_ambiguous && <p className="text-sm text-kind-2">В Assets несколько совпадений — привязка не установлена.</p>}
    </div>
    <p className="rounded border border-border p-3 text-sm text-text-secondary">Показаны настройки из выгрузки. Наличие маршрута в конфигурации не подтверждает доступность из интернета или возможность эксплуатации уязвимости.</p>
    {!!doc.warnings.length && <details className="rounded border border-border p-3 text-sm"><summary className="cursor-pointer">Ограничения разбора: {doc.warnings.length}</summary><ul className="mt-2 list-disc space-y-1 pl-5">{doc.warnings.map(w => <li key={w}>{w}</li>)}</ul></details>}
    <div className="flex flex-wrap gap-2">{[['routes', 'Маршруты'], ['settings', 'Настройки'], ['graph', 'Связи'], ['sources', 'Источники'], ['history', 'История']].map(([key, title]) => <Button key={key} aria-pressed={tab === key} variant={tab === key ? 'primary' : 'secondary'} onClick={() => { setTab(key); setSearch('') }}>{title}</Button>)}</div>
    {['routes', 'settings', 'graph'].includes(tab) && <label className="block text-sm">Виртуальный сервер<select className={`${FIELD} mt-1 w-full`} aria-label="Виртуальный сервер" value={siteIndex} onChange={e => { setSiteIndex(Number(e.target.value)); setRouteIndex(0) }}>{doc.servers.map((s, i) => <option key={i} value={i}>{s.names.join(', ') || 'Без server_name'} — {s.listen.join(', ') || 'listen не задан явно'} ({i + 1})</option>)}</select></label>}
    {['routes', 'settings', 'sources'].includes(tab) && <input className={`${FIELD} w-full`} aria-label="Поиск в снимке" placeholder="Поиск по маршрутам, настройкам и источникам" value={search} onChange={e => setSearch(e.target.value)} />}
    {tab === 'routes' && site?.routes.filter(r => `${r.match} ${r.destination} ${r.targets.map(t => t.host).join(' ')}`.toLowerCase().includes(needle)).map((r, i) => <details key={i} className="rounded border border-border p-3 text-sm">
      <summary className="cursor-pointer break-all"><span className="font-mono">{r.parents.length ? r.parents.join(' → ') + ' → ' : ''}{r.match}</span> · {ACTION[r.action]} · {r.destination || 'назначение не определено'}</summary>
      <div className="mt-3 space-y-3"><p className="text-text-secondary">{r.file}:{r.line}</p>{r.targets.map((t, n) => <p key={n}>{t.dynamic ? 'Динамическая цель' : t.host} {t.port !== null ? `:${t.port}` : ''}{t.local ? ' — на том же сервере' : ''} {t.parameters}</p>)}<Settings items={r.settings} /><Button onClick={() => showSource(r.file)}><FileCode2 size={14} />Источник</Button></div>
    </details>)}
    {tab === 'settings' && site && <Settings items={site.settings.filter(s => `${s.name} ${s.value}`.toLowerCase().includes(needle))} />}
    {tab === 'graph' && site && route && <div className="space-y-3"><label className="block text-sm">Маршрут<select className={`${FIELD} mt-1 w-full`} aria-label="Маршрут" value={routeIndex} onChange={e => setRouteIndex(Number(e.target.value))}>{site.routes.map((r, i) => <option key={i} value={i}>{r.match} → {r.destination || ACTION[r.action]}</option>)}</select></label><RouteGraph route={route} hostname={data.hostname} entry={[...site.names, ...site.listen].join(' · ') || 'Не задан явно'} /></div>}
    {tab === 'sources' && <div className="space-y-3"><p className="text-sm text-text-secondary">Директивы с номерами строк исходных файлов. Комментарии и произвольные значения скрыты; это представление не предназначено для восстановления конфигурации.</p><select className={`${FIELD} w-full`} aria-label="Исходный файл" value={sourceIndex} onChange={e => setSourceIndex(Number(e.target.value))}>{doc.sources.map((s, i) => <option key={s.path} value={i}>{s.path}</option>)}</select><div className="overflow-x-auto rounded border border-border p-3 font-mono text-xs">{source?.directives.filter(s => `${s.name} ${s.value}`.toLowerCase().includes(needle)).map((s, i) => <div key={i} className="whitespace-pre"><span className="mr-4 inline-block w-8 text-right text-text-secondary">{s.line}</span>{'  '.repeat(s.depth ?? 0)}{s.name} {s.value}{s.block ? ' {' : ';'}</div>)}</div></div>}
    {tab === 'history' && <div className="space-y-2"><p className="text-sm text-text-secondary">Последние 50 снимков. Выбор открывает сохранённую конфигурацию на момент импорта.</p>{history.error && <p role="alert">{history.error.message}</p>}{history.data?.items.map(s => <div key={s.id}><Button disabled={s.id === id} onClick={() => navigate(`/radar/nginx/${s.id}`)}>{dateText(s.imported_at)} · {s.sha256.slice(0, 12)}{s.id === id ? ' · открыт' : ''}</Button></div>)}</div>}
  </div>
}
