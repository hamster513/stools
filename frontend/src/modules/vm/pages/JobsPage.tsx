import { ListChecks, XCircle } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useCancelJob, useJobs } from '@/modules/vm/api/queries'
import { JOB_KIND_LABELS, STAGE_LABELS, type Job } from '@/modules/vm/api/types'
import { ElapsedTime, JobProgress, RunningStatus, SqlQueryStatus } from '@/modules/vm/components/JobProgress'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { ColGroup, ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'

const STATUS_LABEL: Record<Job['status'], string> = {
  running: 'идёт',
  done: 'готово',
  failed: 'ошибка',
  cancelled: 'отменена',
}

const COLUMNS: ColumnDef[] = [
  { key: 'job', label: 'Задача', width: 144 },
  { key: 'stage', label: 'Стадия', width: 104 },
  { key: 'status', label: 'Статус', width: 104 },
  { key: 'progress', label: 'Прогресс', width: 128 },
  { key: 'message', label: 'Сообщение', width: 160, flex: true },
  { key: 'started', label: 'Запуск', width: 120 },
  { key: 'duration', label: 'Длительность', width: 124, align: 'right' },
  { key: 'actions', label: 'Действие', width: 136, resizable: false },
]

function durationSeconds(job: Job): number {
  const start = new Date(job.started_at).getTime()
  const end = job.finished_at ? new Date(job.finished_at).getTime() : Date.now()
  return Math.max(0, Math.round((end - start) / 1000))
}

function when(iso: string): string {
  return new Date(iso).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })
}

export function JobsPage() {
  // Ход задач аудитор видит целиком; останавливает их тот, кто запускает.
  const { write } = useCan()
  const jobs = useJobs()
  const cancel = useCancelJob()
  const cols = useColumnWidths('vm-jobs-columns', COLUMNS)

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
          Активные задачи показаны сверху. Отмена проверяется между пакетами. Во время записи снимка
          начатая операция PostgreSQL выполняется до конца.
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
          <table className="w-full text-xs" style={cols.tableStyle}>
            <ColGroup cols={cols} />
            <thead className="bg-surface text-[11px] tracking-wide text-text-secondary uppercase">
              <tr>
                <ResizableHeader cols={cols} className="px-3 py-2" content={{ actions: <span className="sr-only">Действие</span> }} />
              </tr>
            </thead>
            <tbody>
              {jobs.data.map((j) => (
                <tr key={j.id} className="border-t border-grid align-top">
                  <td className="px-3 py-2 break-words text-text">
                    <span className="font-mono text-text-secondary">#{j.id}</span> {JOB_KIND_LABELS[j.kind] ?? j.kind}
                  </td>
                  <td className="px-3 py-2 break-words text-text-secondary">{STAGE_LABELS[j.stage] ?? j.stage}</td>
                  <td className="px-3 py-2">
                    <span
                      className={cn(
                        j.status === 'running' && 'text-focus-ring',
                        j.status === 'done' && 'text-kind-accepted',
                        j.status === 'failed' && 'text-kind-1',
                        j.status === 'cancelled' && 'text-text-secondary',
                      )}
                    >
                      {j.status === 'running' ? <RunningStatus job={j} /> : STATUS_LABEL[j.status]}
                      {j.cancel_requested && j.status === 'running' && ' (отмена запрошена)'}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <JobProgress job={j} />
                  </td>
                  <td className="px-3 py-2 break-words text-text-secondary">
                    {j.message !== j.error && j.message}
                    {j.error && <div className="text-kind-1">{j.error}</div>}
                    <SqlQueryStatus job={j} />
                  </td>
                  <td className="truncate px-3 py-2 text-text-secondary" title={`${when(j.started_at)} ${j.started_by}`}>
                    {when(j.started_at)} <span className="font-mono">{j.started_by}</span>
                  </td>
                  <td className="truncate px-3 py-2 text-right font-mono tabular-nums text-text-secondary"><ElapsedTime seconds={durationSeconds(j)} /></td>
                  <td className="px-3 py-2 text-right">
                    {write && j.status === 'running' && (
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
