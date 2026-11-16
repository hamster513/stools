import { synchronizationPost } from './routes.ts'
import { taskKey, type QueueRun } from './types.ts'

export type Send = <T>(path: string, init?: RequestInit) => Promise<T>
export const QUEUE_ACCEPTED = 'stools:sync-queue-accepted'

export async function queuedPost<T>(path: string, body: unknown, send: Send, error: (status: number, message: string) => Error): Promise<T> {
  const match = synchronizationPost(path, body)
  const post = { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) }
  if (!match) return send<T>(path, post)
  let run = await send<QueueRun>('/api/settings/sync-runs', {
    method: 'POST', body: JSON.stringify({ tasks: [match.task] }),
  })
  window.dispatchEvent(new CustomEvent(QUEUE_ACCEPTED, { detail: { id: run.id, status: run.status } }))
  // The server owns execution. Navigation or closing the tab cannot discard the accepted request.
  // Existing module progress widgets still receive their native job id once the step starts.
  for (;;) {
    const step = run.steps.find(s => s.is_root && s.key === taskKey(match.task))
    if (!step) throw error(409, 'В запуске отсутствует запрошенная задача')
    if (match.response === 'job' && step.job_id !== null) return { job_id: step.job_id } as T
    if (match.response === 'result' && ['done', 'partial', 'failed'].includes(step.status) && step.result !== null) return step.result as T
    if (['failed', 'blocked', 'cancelled'].includes(step.status) || run.status === 'cancelled') {
      throw error(409, step.message || 'Запуск отменён или завершился ошибкой; подробности — в общей очереди')
    }
    await new Promise(resolve => setTimeout(resolve, 2000))
    run = await send<QueueRun>(`/api/settings/sync-runs/${run.id}`)
  }
}
