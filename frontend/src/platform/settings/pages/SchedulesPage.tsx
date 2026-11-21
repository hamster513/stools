import { Fragment, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type ApiRequestError } from '@/api/client'
import { Link } from '@/lib/router'
import { useMe } from '@/api/auth'
import { Button } from '@/components/ui/Button'
import { atLeast } from '@/platform/access/types'
import { ScheduleBlock } from '@/platform/collector/ScheduleBlock'
import type { ScheduleIn, ScheduleView } from '@/platform/collector/types'
import { DependencyEditor } from '@/platform/syncQueue/DependencyEditor'
import { QueuePanel } from '@/platform/syncQueue/QueuePanel'
import type { QueueRun, QueueTask, TaskRequest } from '@/platform/syncQueue/types'
import { scheduleText } from '../scheduleText'

const MODULES = { radar: 'Радар', platform: 'Платформа', ad: 'Active Directory', ksc: 'Антивирус', assets: 'Активы', vm: 'Уязвимости', siem: 'SIEM', attack: 'ATT&CK' }
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
  const save = useMutation<ScheduleView, ApiRequestError, ScheduleIn>({ mutationFn: data => api.put(url, data), onSuccess: refresh })
  const remove = useMutation<void, ApiRequestError, void>({ mutationFn: () => api.del(url), onSuccess: refresh })
  return <ScheduleBlock title={task.title} enableLabel="Включить запуск по расписанию" current={task.schedule}
    note="В назначенное время задача попадёт в общую очередь вместе с зависимостями." save={save} remove={remove} />
}

export function SchedulesPage() {
  const { data: me } = useMe()
  const qc = useQueryClient()
  const [open, setOpen] = useState('')
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const query = useQuery<Catalog, ApiRequestError>({ queryKey: ['sync-schedules'], queryFn: () => api.get('/api/settings/schedules'), refetchInterval: 30_000 })
  const queueTasks = useQuery<{ items: QueueTask[] }, ApiRequestError>({
    queryKey: ['sync-tasks'], queryFn: () => api.get('/api/settings/sync-tasks'), refetchInterval: 30_000,
  })
  const submit = useMutation<QueueRun, ApiRequestError, TaskRequest[]>({
    mutationFn: tasks => api.post('/api/settings/sync-runs', { tasks }),
    onSuccess: () => { setSelected(new Set()); qc.invalidateQueries({ queryKey: ['sync-runs'] }) },
  })
  const tasks = queueTasks.data?.items ?? []
  const runnable = tasks.filter(t => t.can_run && t.kind !== 'storage_cleanup')
  const data = query.data
  const missing = data && me ? CONNECTIONS.filter(c => atLeast(me.access, c.module, 'read') &&
    !data.items.some(task => task.module === c.module && task.kind === c.kind)) : []
  const when = (iso?: string | null) => iso && data
    ? new Date(iso).toLocaleString('ru-RU', { timeZone: data.tz, dateStyle: 'short', timeStyle: 'short' }) : 'Нет подтверждения'
  const enqueue = (items: QueueTask[]) => submit.mutate(items.map(({ module, kind, target_id }) => ({ module, kind, target_id })))
  return <div className="mx-auto w-full max-w-7xl space-y-4 p-4 sm:p-6">
    <h1 className="text-xl font-semibold">Расписание и очередь задач</h1>
    <p className="text-sm text-text-secondary">Выберите несколько обновлений или задайте дни и время. Зависимости и свежесть проверяются перед выполнением. {data && `Часовой пояс расписания — ${data.tz}.`}</p>
    {query.isLoading && <p role="status">Загрузка расписаний…</p>}
    {query.isError && <p role="alert">{query.error.message} <Button variant="ghost" onClick={() => query.refetch()}>Повторить</Button></p>}
    {queueTasks.isError && <p role="alert">{queueTasks.error.message}</p>}
    {submit.isError && <p role="alert" className="text-risk-critical">{submit.error.message}</p>}
    {submit.isSuccess && <p role="status" className="text-sm">Запуск #{submit.data.id} принят. Можно продолжать работу; состояние показано в очереди ниже.</p>}
    {!!runnable.length && <div className="flex flex-wrap items-center gap-3">
      <Button variant="primary" disabled={!selected.size} loading={submit.isPending}
        onClick={() => enqueue(runnable.filter(t => selected.has(t.key)))}>В очередь выбранные ({selected.size})</Button>
      <Button variant="ghost" onClick={() => setSelected(new Set(runnable.slice(0, 100).map(t => t.key)))}>Выбрать доступные</Button>
      {!!selected.size && <Button variant="ghost" onClick={() => setSelected(new Set())}>Снять выбор</Button>}
    </div>}
    {data && !data.items.length && !missing.length && <p>Нет доступных источников синхронизации.</p>}
    {!!data?.items.length && <div className="overflow-x-auto"><table className="w-full text-left text-sm">
      <thead className="text-xs text-text-secondary"><tr>{['Выбор', 'Источник', 'Расписание', 'Данные подтверждены', 'Зависимости', 'Следующий запуск', 'Действия'].map(h => <th key={h} className="p-2">{h}</th>)}</tr></thead>
      <tbody>{data.items.map(task => {
        const key = `${task.module}/${task.kind}/${task.target_id}`
        const meta = tasks.find(t => t.key === key)
        const canRun = meta?.can_run && task.kind !== 'storage_cleanup'
        const s = task.schedule
        return <Fragment key={key}><tr className="border-t border-grid align-top">
          <td className="p-2"><input type="checkbox" aria-label={`Выбрать: ${task.title}`} checked={selected.has(key)} disabled={!canRun || (!selected.has(key) && selected.size >= 100)}
            onChange={e => setSelected(prev => { const next = new Set(prev); if (e.target.checked) next.add(key); else next.delete(key); return next })} /></td>
          <td className="min-w-48 p-2"><div className="text-xs text-text-secondary">{MODULES[task.module]}</div>{task.title}
            {s?.last_run_at && <div className="mt-1 text-xs text-text-secondary">Последний запуск расписанием: {when(s.last_run_at)}</div>}
          </td>
          <td className="p-2">{scheduleText(s)}</td>
          <td className="p-2 text-xs">{when(meta?.last_updated_at)}</td>
          <td className="p-2">{meta ? meta.dependencies.length + meta.hidden_dependencies : '—'}</td>
          <td className="p-2 text-xs">{s?.enabled ? when(s.next_run_at) : '—'}</td>
          <td className="p-2"><div className="flex flex-wrap gap-1">
            {canRun && <Button variant="ghost" disabled={submit.isPending} onClick={() => enqueue([meta!])}>В очередь</Button>}
            {meta?.can_run && task.kind === 'storage_cleanup' && <Link className="p-2 text-primary hover:underline" to="/settings/storage">Расчёт очистки</Link>}
            {me && atLeast(me.access, task.module, 'admin') && <Button variant="ghost" aria-expanded={open === key}
              aria-label={`Настроить задачу: ${task.title}`} onClick={() => setOpen(open === key ? '' : key)}>{open === key ? 'Свернуть' : 'Настроить'}</Button>}
          </div></td>
        </tr>{open === key && <tr><td colSpan={7} className="space-y-4 border-t border-grid bg-surface p-4">
          <Editor key={s?.id ?? 'new'} task={task} />
          {meta && <DependencyEditor key={key} task={meta} tasks={tasks} />}
        </td></tr>}</Fragment>
      })}</tbody></table></div>}
    {!!missing.length && <section className="space-y-2 border-t border-grid pt-3">
      <h2 className="font-semibold">Источники без подключений</h2>
      <p className="text-sm text-text-secondary">После сохранения подключения здесь появится его расписание.</p>
      <ul className="space-y-1 text-sm">{missing.map(c => <li key={c.module + c.kind}>{c.title}
        {me && atLeast(me.access, c.module, 'admin') && <Link className="ml-3 text-primary hover:underline"
          to={`/settings/${c.module}#${c.anchor}`}>Настроить подключение</Link>}</li>)}</ul>
    </section>}
    <QueuePanel tasks={tasks} />
  </div>
}
