import { ListChecks, XCircle } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useCancelJob, useJobs } from '@/modules/vm/api/queries'
import { JOB_KIND_LABELS, STAGE_LABELS, type Job } from '@/modules/vm/api/types'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'

const STATUS_LABEL: Record<Job['status'], string> = {
  running: 'идёт',
  done: 'готово',
  failed: 'ошибка',
  cancelled: 'отменена',
}

function duration(job: Job): string {
  const start = new Date(job.started_at).getTime()
  const end = job.finished_at ? new Date(job.finished_at).getTime() : Date.now()
  const s = Math.max(0, Math.round((end - start) / 1000))
  if (s < 60) return `${s} с`
  if (s < 3600) return `${Math.floor(s / 60)} мин ${s % 60} с`
  return `${Math.floor(s / 3600)} ч ${Math.floor((s % 3600) / 60)} мин`
}

function when(iso: string): string {
  return new Date(iso).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })
}

export function JobsPage() {
  // Ход задач аудитор видит целиком; останавливает их тот, кто запускает.
  const { write } = useCan()
  const jobs = useJobs()
  const cancel = useCancelJob()

  if (jobs.isLoading) return <FullPageSpinner />
  if (jobs.isError || !jobs.data) {
    const msg = jobs.error instanceof ApiRequestError ? jobs.error.message : 'Не удалось загрузить задачи'
    return <div className="p-6"><ErrorState message={msg} onRetry={() => jobs.refetch()} /></div>
  }

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-4">
        <h1 className="text-base font-semibold text-text">Задачи</h1>
        <p className="max-w-2xl text-xs text-text-secondary">
          Импорт, справочники и пересчёт идут в фоне. Идущие — сверху; отмена срабатывает между
          пакетами строк, а после стадии записи импорт уже не останавливается: данные заменены.
        </p>
      </div>

      {jobs.data.length === 0 ? (
        <EmptyState
          icon={ListChecks}
          title="Задач ещё не было"
          description="Запустите импорт из MaxPatrol VM или загрузку справочника в настройках — здесь появится прогресс."
        />
      ) : (
        <div className="overflow-x-auto rounded border border-grid">
          <table className="w-full min-w-[900px] text-xs">
            <thead className="bg-surface text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
              <tr>
                <th className="px-3 py-2 text-left">Задача</th>
                <th className="px-3 py-2 text-left">Стадия</th>
                <th className="px-3 py-2 text-left">Статус</th>
                <th className="w-48 px-3 py-2 text-left">Прогресс</th>
                <th className="px-3 py-2 text-left">Сообщение</th>
                <th className="px-3 py-2 text-left">Запуск</th>
                <th className="px-3 py-2 text-right">Длительность</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {jobs.data.map((j) => (
                <tr key={j.id} className="border-t border-grid align-top">
                  <td className="px-3 py-2 text-text">
                    <span className="font-mono text-text-secondary">#{j.id}</span> {JOB_KIND_LABELS[j.kind] ?? j.kind}
                  </td>
                  <td className="px-3 py-2 text-text-secondary">{STAGE_LABELS[j.stage] ?? j.stage}</td>
                  <td className="px-3 py-2">
                    <span
                      className={cn(
                        j.status === 'running' && 'text-focus-ring',
                        j.status === 'done' && 'text-kind-accepted',
                        j.status === 'failed' && 'text-kind-1',
                        j.status === 'cancelled' && 'text-text-secondary',
                      )}
                    >
                      {STATUS_LABEL[j.status]}
                      {j.cancel_requested && j.status === 'running' && ' (останавливается)'}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    {j.status === 'running' ? (
                      <div>
                        <div className="h-1.5 w-full overflow-hidden rounded-full bg-grid">
                          <div className="h-full rounded-full bg-primary transition-[width] duration-300" style={{ width: `${j.progress}%` }} />
                        </div>
                        <div className="mt-1 font-mono text-[11px] tabular-nums text-text-secondary">
                          {j.total ? `${j.processed.toLocaleString('ru-RU')} / ${j.total.toLocaleString('ru-RU')}` : j.processed ? j.processed.toLocaleString('ru-RU') : ''}
                        </div>
                      </div>
                    ) : (
                      <span className="font-mono tabular-nums text-text-secondary">{j.processed ? j.processed.toLocaleString('ru-RU') : ''}</span>
                    )}
                  </td>
                  <td className="max-w-[320px] px-3 py-2 text-text-secondary">
                    {j.error ? <span className="text-kind-1">{j.error}</span> : j.message}
                  </td>
                  <td className="px-3 py-2 whitespace-nowrap text-text-secondary">
                    {when(j.started_at)} <span className="font-mono">{j.started_by}</span>
                  </td>
                  <td className="px-3 py-2 text-right font-mono tabular-nums whitespace-nowrap text-text-secondary">{duration(j)}</td>
                  <td className="px-3 py-2 text-right">
                    {write && j.status === 'running' && !j.cancel_requested && (
                      <Button variant="ghost" onClick={() => cancel.mutate(j.id)} aria-label={`Отменить задачу ${j.id}`}>
                        <XCircle size={13} aria-hidden /> отменить
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
