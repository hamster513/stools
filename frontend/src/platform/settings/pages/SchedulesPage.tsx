import { Fragment, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type ApiRequestError } from '@/api/client'
import { Link } from '@/lib/router'
import { useMe } from '@/api/auth'
import { Button } from '@/components/ui/Button'
import { atLeast } from '@/platform/access/types'
import { ScheduleBlock } from '@/platform/collector/ScheduleBlock'
import type { ScheduleIn, ScheduleView } from '@/platform/collector/types'
import { scheduleText } from '../scheduleText'

const MODULES = { ad: 'Active Directory', ksc: 'Антивирус', assets: 'Активы', vm: 'Уязвимости', siem: 'SIEM', attack: 'ATT&CK' }
const CONNECTIONS = [
  { module: 'ad', kind: 'collect', title: 'Active Directory', anchor: 'connections' },
  { module: 'ksc', kind: 'collect', title: 'Антивирус (KSC)', anchor: 'connections' },
  { module: 'assets', kind: 'dns', title: 'DNS', anchor: 'dns' },
  { module: 'assets', kind: 'rt', title: 'RackTables', anchor: 'racktables' },
] as const
interface Task { module: keyof typeof MODULES; kind: string; target_id: number; title: string; schedule: ScheduleView | null }
interface Catalog { items: Task[]; tz: string }

function Editor({ task }: { task: Task }) {
  const qc = useQueryClient()
  const url = `/api/settings/schedules/${task.module}/${task.kind}/${task.target_id}`
  const refresh = () => qc.invalidateQueries({ predicate: ({ queryKey }) => {
    const key = String(queryKey[0])
    return key === 'sync-schedules' || key.startsWith(task.module)
  } })
  const save = useMutation<ScheduleView, ApiRequestError, ScheduleIn>({ mutationFn: (data) => api.put(url, data), onSuccess: refresh })
  const remove = useMutation<void, ApiRequestError, void>({ mutationFn: () => api.del(url), onSuccess: refresh })
  return <ScheduleBlock title={task.title} enableLabel="Включить запуск по расписанию" current={task.schedule}
    note="При занятом источнике запуск ожидает следующей проверки планировщика." save={save} remove={remove} />
}

export function SchedulesPage() {
  const { data: me } = useMe()
  const [open, setOpen] = useState('')
  const query = useQuery<Catalog, ApiRequestError>({ queryKey: ['sync-schedules'], queryFn: () => api.get('/api/settings/schedules'), refetchInterval: 60_000 })
  const data = query.data
  const missing = data && me ? CONNECTIONS.filter((c) => atLeast(me.access, c.module, 'read') &&
    !data.items.some((task) => task.module === c.module && task.kind === c.kind)) : []
  const when = (iso?: string | null) => iso && data
    ? new Date(iso).toLocaleString('ru-RU', { timeZone: data.tz, dateStyle: 'short', timeStyle: 'short' }) : '—'
  return <div className="mx-auto w-full max-w-6xl space-y-4 p-6">
    <h1 className="text-xl font-semibold">Расписание синхронизаций</h1>
    <p className="text-sm text-text-secondary">У каждого источника свои дни и время запуска. {data && `Часовой пояс — ${data.tz}.`}</p>
    {query.isLoading && <p role="status">Загрузка расписаний…</p>}
    {query.isError && <p role="alert">{query.error.message} <Button variant="ghost" onClick={() => query.refetch()}>Повторить</Button></p>}
    {data && !data.items.length && !missing.length && <p>Нет доступных источников синхронизации.</p>}
    {!!data?.items.length && <div className="overflow-x-auto"><table className="w-full text-left text-sm">
      <thead className="text-xs text-text-secondary"><tr>{['Источник', 'Расписание', 'Прошлый запуск', 'Следующий запуск', ''].map((h) => <th key={h} className="p-2">{h}</th>)}</tr></thead>
      <tbody>{data.items.map((task) => {
        const key = `${task.module}/${task.kind}/${task.target_id}`
        const s = task.schedule
        return <Fragment key={key}><tr className="border-t border-grid">
          <td className="p-2"><div className="text-xs text-text-secondary">{MODULES[task.module]}</div>{task.title}</td>
          <td className="p-2">{scheduleText(s)}</td><td className="p-2">{when(s?.last_run_at)}</td>
          <td className="p-2">{when(s?.enabled ? s.next_run_at : null)}</td>
          <td className="p-2">{me && atLeast(me.access, task.module, 'admin') &&
            <Button variant="ghost" aria-expanded={open === key} aria-label={`Расписание: ${task.title}`} onClick={() => setOpen(open === key ? '' : key)}>
              {open === key ? 'Свернуть' : s ? 'Изменить' : 'Настроить'}</Button>}</td>
        </tr>{open === key && <tr><td colSpan={5} className="border-t border-grid bg-surface p-4"><Editor key={s?.id ?? 'new'} task={task} /></td></tr>}</Fragment>
      })}</tbody></table></div>}
    {!!missing.length && <section className="space-y-2 border-t border-grid pt-3">
      <h2 className="font-semibold">Источники без подключений</h2>
      <p className="text-sm text-text-secondary">После сохранения подключения здесь появится его расписание.</p>
      <ul className="space-y-1 text-sm">{missing.map((c) => <li key={c.module + c.kind}>{c.title}
        {me && atLeast(me.access, c.module, 'admin') && <Link className="ml-3 text-primary hover:underline"
          to={`/settings/${c.module}#${c.anchor}`}>Настроить подключение</Link>}</li>)}</ul>
    </section>}
  </div>
}
