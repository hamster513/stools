import type { UseMutationResult, UseQueryResult } from '@tanstack/react-query'
import { ListChecks, XCircle } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { cn } from '@/lib/cn'
import type { Job } from './types'

const STATUS_LABEL: Record<Job['status'], string> = { running: 'идёт', done: 'готово', failed: 'ошибка', cancelled: 'отменена' }

function duration(job: Job): string {
  const s = Math.max(0, Math.round(((job.finished_at ? new Date(job.finished_at).getTime() : Date.now()) - new Date(job.started_at).getTime()) / 1000))
  return s < 60 ? `${s} с` : `${Math.floor(s / 60)} мин ${s % 60} с`
}

/** Экран «Задачи» модуля: фоновые задачи, идущие — сверху; отмена — тому, кому разрешено. */
export function CollectorJobsPage({ jobs, cancel, canCancel, kindLabels, stageLabels, about, emptyDescription }: {
  jobs: UseQueryResult<Job[], ApiRequestError>
  cancel: UseMutationResult<void, ApiRequestError, number>
  canCancel: boolean
  kindLabels: Record<string, string>
  stageLabels: Record<string, string>
  about: string
  emptyDescription: string
}) {
  if (jobs.isLoading) return <FullPageSpinner />
  if (jobs.isError || !jobs.data) {
    const msg = jobs.error instanceof ApiRequestError ? jobs.error.message : 'Не удалось загрузить задачи'
    return <div className="p-6"><ErrorState message={msg} onRetry={() => jobs.refetch()} /></div>
  }
  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-4">
        <h1 className="text-base font-semibold text-text">Задачи</h1>
        <p className="max-w-2xl text-xs text-text-secondary">{about}</p>
      </div>
      {jobs.data.length === 0 ? (
        <EmptyState icon={ListChecks} title="Задач ещё не было" description={emptyDescription} />
      ) : (
        <div className="overflow-x-auto rounded border border-grid">
          <table className="w-full min-w-[800px] text-xs">
            <thead className="bg-surface text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
              <tr><th className="px-3 py-2 text-left">Задача</th><th className="px-3 py-2 text-left">Стадия</th><th className="px-3 py-2 text-left">Статус</th><th className="px-3 py-2 text-left">Сообщение</th><th className="px-3 py-2 text-left">Запуск</th><th className="px-3 py-2 text-right">Длительность</th><th></th></tr>
            </thead>
            <tbody>
              {jobs.data.map((j) => (
                <tr key={j.id} className="border-t border-grid align-top">
                  <td className="px-3 py-2 text-text"><span className="font-mono text-text-secondary">#{j.id}</span> {kindLabels[j.kind] ?? j.kind}</td>
                  <td className="px-3 py-2 text-text-secondary">{stageLabels[j.stage] ?? j.stage}</td>
                  <td className={cn('px-3 py-2', j.status === 'running' && 'text-focus-ring', j.status === 'done' && 'text-kind-accepted', j.status === 'failed' && 'text-kind-1', j.status === 'cancelled' && 'text-text-secondary')}>{STATUS_LABEL[j.status]}</td>
                  <td className="max-w-[360px] px-3 py-2 text-text-secondary">{j.error ? <span className="text-kind-1">{j.error}</span> : j.message}</td>
                  <td className="px-3 py-2 whitespace-nowrap text-text-secondary">{new Date(j.started_at).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })} <span className="font-mono">{j.started_by}</span></td>
                  <td className="px-3 py-2 text-right font-mono tabular-nums whitespace-nowrap text-text-secondary">{duration(j)}</td>
                  <td className="px-3 py-2 text-right">{canCancel && j.status === 'running' && !j.cancel_requested && <Button variant="ghost" onClick={() => cancel.mutate(j.id)} aria-label={`Отменить задачу ${j.id}`}><XCircle size={13} aria-hidden /></Button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
