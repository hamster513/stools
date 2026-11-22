import { useState } from 'react'
import { Radar, Settings } from 'lucide-react'
import { AppShell } from '@/components/layout/AppShell'
import { Button } from '@/components/ui/Button'
import { FIELD } from '@/components/ui/Field'
import { useRouter } from '@/lib/router'
import { useCan } from '@/lib/can'
import { dateText, useServers } from './api'
import { PathsPage } from './PathsPage'
import { NettracePage } from './NettracePage'
import { SnapshotPage } from './SnapshotPage'

function ServersPage() {
  const { navigate } = useRouter()
  const [q, setQ] = useState('')
  const [offset, setOffset] = useState(0)
  const query = useServers(q, offset)
  return <div className="space-y-4">
    <p className="text-sm text-text-secondary">Все импортированные серверы nginx: внешние и внутренние. Найдите сервер, домен, адрес или backend и откройте его маршруты.</p>
    <input className={`${FIELD} w-full`} aria-label="Поиск серверов nginx" placeholder="Сервер, домен, адрес или backend" value={q} onChange={e => { setQ(e.target.value); setOffset(0) }} />
    {query.isPending && <p role="status">Загрузка серверов…</p>}
    {query.error && <div role="alert"><p>{query.error.message}</p><Button onClick={() => query.refetch()}>Повторить</Button></div>}
    {query.data && <>
      <p className="text-sm text-text-secondary">Найдено серверов: {query.data.total}</p>
      {!query.data.total && <p className="rounded border border-border p-4 text-sm">{q ? 'Совпадений нет.' : 'Конфигурации ещё не загружены. Добавьте файлы в «Настройки → Радар».'}</p>}
      {!!query.data.items.length && <div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead><tr className="border-b border-border">{['Сервер', 'Домены / адреса', 'Маршруты', 'Доступ извне', 'Импорт'].map(t => <th className="p-3" key={t}>{t}</th>)}</tr></thead><tbody>{query.data.items.map(s => <tr key={s.id} className="border-b border-border align-top hover:bg-row-hover"><td className="p-3"><button className="break-all text-left text-primary underline" onClick={() => navigate(`/radar/nginx/${s.id}`)}>{s.hostname}</button>{s.warnings > 0 && <p className="mt-1 text-xs text-kind-2">Ограничений: {s.warnings}</p>}</td><td className="max-w-sm p-3"><details><summary className="cursor-pointer break-all">{s.domains[0] || 'Без server_name'} · адресов: {s.listen.length}</summary><p className="mt-2 break-all">{s.domains.join(', ')}</p><p className="break-all text-text-secondary">{s.listen.join(', ') || 'listen не задан явно'}</p></details></td><td className="p-3">{s.routes}</td><td className="p-3 text-text-secondary">Не установлен</td><td className="whitespace-nowrap p-3">{dateText(s.imported_at)}</td></tr>)}</tbody></table></div>}
      <div className="flex items-center gap-3"><Button disabled={!offset} onClick={() => setOffset(Math.max(0, offset - 50))}>Назад</Button><span className="text-sm">Страница {offset / 50 + 1}</span><Button disabled={offset + 50 >= query.data.total} onClick={() => setOffset(offset + 50)}>Далее</Button></div>
    </>}
  </div>
}

export function RadarModule() {
  const { path, navigate } = useRouter()
  const { write } = useCan('radar')
  const match = /^\/radar\/nginx\/(\d+)$/.exec(path)
  return <AppShell><div className="h-full min-h-0 overflow-auto p-4 md:p-6"><div className="mx-auto max-w-7xl space-y-5">
    <div className="flex flex-wrap items-center justify-between gap-3"><h1 className="flex items-center gap-2 text-xl font-semibold"><Radar className="text-primary" />Радар</h1>{write && <Button onClick={() => navigate('/settings/radar')}><Settings size={16} />Настройки и импорт</Button>}</div>
    {!match && <div className="flex gap-2"><Button variant={path === '/radar' ? 'primary' : 'secondary'} onClick={() => navigate('/radar')}>Nginx</Button><Button variant={path.startsWith('/radar/paths') ? 'primary' : 'secondary'} onClick={() => navigate('/radar/paths')}>Пути к приложениям</Button><Button variant={path.startsWith('/radar/nettrace') ? 'primary' : 'secondary'} onClick={() => navigate('/radar/nettrace')}>NetTrace</Button><Button variant={path === '/radar/scanfactory' ? 'primary' : 'secondary'} onClick={() => navigate('/radar/scanfactory')}>ScanFactory</Button></div>}
    {match ? <SnapshotPage key={match[1]} id={Number(match[1])} /> : path.startsWith('/radar/paths') ? <PathsPage /> : path.startsWith('/radar/nettrace') ? <NettracePage /> : path === '/radar/scanfactory' ? <p className="rounded border border-border p-4 text-sm text-text-secondary">ScanFactory пока не подключён. Внешние наблюдения отсутствуют; доступность импортированных сервисов из интернета не подтверждена.</p> : <ServersPage />}
  </div></div></AppShell>
}
