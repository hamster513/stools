import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type ApiRequestError } from '@/api/client'
import { useMe } from '@/api/auth'
import { atLeast, type Area } from '@/platform/access/types'
import { Button } from '@/components/ui/Button'
import { STATUS, active, type QueueRun, type QueueTask } from './types'

export function QueuePanel({ tasks }: { tasks: QueueTask[] }) {
  const { data: me } = useMe()
  const [before, setBefore] = useState<number | null>(null)
  const qc = useQueryClient()
  const query = useQuery<{ items: QueueRun[]; next_before: number | null }, ApiRequestError>({
    queryKey: ['sync-runs', before], queryFn: () => api.get('/api/settings/sync-runs' + (before ? `?before=${before}` : '')),
    refetchInterval: 3000,
  })
  const action = useMutation<unknown, ApiRequestError, { id: number; kind: 'cancel' | 'retry' }>({
    mutationFn: ({ id, kind }) => api.post(`/api/settings/sync-runs/${id}/${kind}`),
    onSuccess: () => { setBefore(null); qc.invalidateQueries({ queryKey: ['sync-runs'] }) },
  })
  const when = (value: string | null) => value ? new Date(value).toLocaleString('ru-RU') : '—'
  return <section className="space-y-3 border-t border-grid pt-5" aria-label="Очередь и результаты запусков">
    <h2 className="text-lg font-semibold">Очередь и результаты</h2>
    <p className="text-sm text-text-secondary">Выполняется одна задача за раз. Очередь сохраняется при закрытии страницы и перезапуске API. Прерванные задачи требуют явного повтора.</p>
    {query.isLoading && <p role="status">Загрузка очереди…</p>}
    {query.isError && <p role="alert">{query.error.message}</p>}
    {action.isError && <p role="alert" className="text-risk-critical">{action.error.message}</p>}
    {!query.data?.items.length && query.isSuccess && <p className="text-sm text-text-secondary">Запусков пока нет.</p>}
    {query.data?.items.map(run => {
      const canManage = !!me && run.steps.every(s => tasks.find(t => t.key === s.key)?.can_run ??
        atLeast(me.access, s.module as Area, s.module === 'platform' || s.module === 'attack' || s.kind.startsWith('ref_') ? 'admin' : 'write'))
      const completed = run.steps.filter(s => ['done', 'fresh'].includes(s.status)).length
      return <details key={run.id} open={active(run.status)} className="rounded border border-border p-3">
        <summary className="cursor-pointer text-sm">
          <strong>Запуск #{run.id} · {STATUS[run.status] ?? run.status}</strong>
          <span className="ml-3 text-text-secondary">{completed}/{run.steps.filter(s => s.status !== 'skipped').length} шагов · {when(run.created_at)} · {run.actor}</span>
        </summary>
        <div className="mt-3 overflow-x-auto">
          <table className="w-full text-left text-sm"><thead><tr className="text-text-secondary">
            <th className="p-2">Задача</th><th className="p-2">Состояние и основание</th><th className="p-2">Данные подтверждены</th>
          </tr></thead><tbody>{run.steps.map(step => <tr key={step.id} className="border-t border-grid">
            <td className="p-2">{step.title}<div className="text-xs text-text-secondary">{step.is_root ? 'Выбрана для запуска' : 'Зависимость'}{step.job_id !== null ? ` · задача #${step.job_id}` : ''}</div></td>
            <td className="p-2"><span className={['failed', 'blocked'].includes(step.status) ? 'text-risk-critical' : ''}>{STATUS[step.status] ?? step.status}</span>
              {step.message && <p className="mt-1 max-w-xl break-words text-xs text-text-secondary">{step.message}</p>}
            </td><td className="whitespace-nowrap p-2 text-xs">{when(step.checked_at)}</td>
          </tr>)}</tbody></table>
        </div>
        {canManage && <div className="mt-3 flex gap-2">
          {active(run.status) && <Button variant="ghost" disabled={run.cancel_requested || action.isPending}
            onClick={() => action.mutate({ id: run.id, kind: 'cancel' })}>{run.cancel_requested ? 'Отмена запрошена' : 'Отменить ожидающие'}</Button>}
          {['partial', 'failed', 'cancelled'].includes(run.status) && !run.steps.some(step => step.kind === 'archive_import') && <Button variant="ghost" disabled={action.isPending}
            onClick={() => action.mutate({ id: run.id, kind: 'retry' })}>Повторить незавершённые</Button>}
        </div>}
      </details>
    })}
    <div className="flex gap-2">
      {before && <Button variant="ghost" onClick={() => setBefore(null)}>Последние запуски</Button>}
      {query.data?.next_before && <Button variant="ghost" onClick={() => setBefore(query.data!.next_before)}>Более ранние</Button>}
    </div>
  </section>
}
