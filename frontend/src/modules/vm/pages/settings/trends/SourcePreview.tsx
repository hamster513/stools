import { useCan } from '@/lib/can'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { TREND_BASE, useTrendMutation, when } from '../../../api/trends'
import type { SourceRun } from '../../../api/trendMonitoring'
import { safeUrl } from '../../trends/publicationUrl'
import { runStates, runTone } from './runStatus'

export function SourcePreview({ jobId, onJob, close }: { jobId: string; onJob: (id: string) => void; close: () => void }) {
  const { admin } = useCan()
  const job = useQuery({ queryKey: ['vm-trends', 'collector-job', jobId], queryFn: () => api.get<SourceRun>(TREND_BASE + '/collector-jobs/' + jobId), refetchInterval: q => ['queued', 'running'].includes(q.state.data?.state ?? 'queued') ? 1500 : false })
  const action = useTrendMutation(async (name: string) => { const result = await api.post<{ job_id?: string }>(TREND_BASE + '/collector-jobs/' + jobId + '/' + name); if (result.job_id) onJob(result.job_id) })
  const row = job.data
  return <section className="space-y-2 rounded border border-grid p-4" aria-live="polite"><div className="flex items-center justify-between"><h4 className="font-semibold">Результат проверки</h4><Button onClick={close}>Закрыть результат</Button></div>
    {job.error && <p role="alert" className="text-kind-1">{job.error.message}</p>}{row && <><p className={runTone(row.state, row.error)}>{runStates[row.state] ?? row.state} · Этап: {row.stage} · {when(row.finished_at || row.created_at)}</p>
      <p>Получено: {row.counters?.fetched ?? 0} · Новых версий: {row.counters?.new_versions ?? 0} · Релевантно: {row.counters?.relevant ?? 0} · Фон: {row.counters?.background ?? 0}</p>
      <p className="text-xs text-text-secondary">Охват: {row.coverage?.kind ?? 'ещё не определён'}{row.coverage?.historical_complete === false ? ' · только доступная текущая лента; полный архив не гарантируется' : ''}{row.coverage?.partial ? ' · окно обработано частично' : ''}</p>
      {row.error && <p role="alert" className="text-kind-1">{row.error}</p>}
      {row.sample?.map((doc, i) => <article key={i} className="border-t border-grid pt-2"><a className="underline" href={safeUrl(doc.url)} target="_blank" rel="noopener noreferrer">{doc.title}</a><p className="text-xs">{when(doc.published_at)} · {doc.identifiers?.join(', ')} · {doc.classification?.category}</p><p className="text-xs">{doc.classification?.reasons.join('; ')}</p><details><summary>Текст</summary><p className="whitespace-pre-wrap text-sm">{doc.text}</p></details></article>)}
      <div className="flex gap-2">{admin && ['queued', 'running'].includes(row.state) && <Button disabled={action.isPending} onClick={() => action.mutate('cancel')}>Остановить</Button>}{admin && ['partial', 'failed', 'cancelled'].includes(row.state) && <Button disabled={action.isPending} onClick={() => action.mutate('resume')}>Продолжить</Button>}</div>
    </>}{action.error && <p role="alert" className="text-kind-1">{action.error.message}</p>}
  </section>
}
