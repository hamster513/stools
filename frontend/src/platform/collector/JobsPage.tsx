import type { UseMutationResult, UseQueryResult } from '@tanstack/react-query'
import { ListChecks, XCircle } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { cn } from '@/lib/cn'
import { useRouter } from '@/lib/router'
import { ColGroup, ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'
import type { Job } from './types'

const COLUMNS: ColumnDef[] = [
  { key: 'job', label: 'Задача', width: 144 },
  { key: 'stage', label: 'Стадия', width: 104 },
  { key: 'status', label: 'Статус', width: 96 },
  { key: 'progress', label: 'Прогресс', width: 128 },
  { key: 'message', label: 'Сообщение', width: 160, flex: true },
  { key: 'started', label: 'Запуск', width: 120 },
  { key: 'duration', label: 'Длительность', width: 124, align: 'right' },
  { key: 'actions', label: 'Действие', width: 192, resizable: false },
]

const STATUS_LABEL: Record<Job['status'], string> = { running: 'идёт', done: 'готово', failed: 'ошибка', cancelled: 'отменена' }

function duration(job: Job): string {
  const s = Math.max(0, Math.round(((job.finished_at ? new Date(job.finished_at).getTime() : Date.now()) - new Date(job.started_at).getTime()) / 1000))
  return s < 60 ? `${s} с` : `${Math.floor(s / 60)} мин ${s % 60} с`
}

/** Полоса прогресса идущей задачи с известным объёмом; без объёма колонка пуста. */
function Progress({ job, total }: { job: Job; total: number }) {
  return (
    <div>
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-grid">
        <div className="h-full rounded-full bg-primary transition-[width] duration-300" style={{ width: `${job.progress}%` }} />
      </div>
      <div className="mt-1 font-mono text-[11px] tabular-nums text-text-secondary">
        {job.progress}% · {job.processed.toLocaleString('ru-RU')} / {total.toLocaleString('ru-RU')}
      </div>
    </div>
  )
}

/**
 * Экран «Задачи» модуля: фоновые задачи, идущие — сверху; снятие — тому, кому разрешено, без подтверждения.
 * Ширины колонок хранятся под `storageKey`, по умолчанию — по модулю из адреса (`/ad/jobs` → `ad-jobs-columns`):
 * экран общий, а модули помнят ширины порознь.
 */
export function CollectorJobsPage({ jobs, cancel, canCancel, kindLabels, stageLabels, about, emptyDescription, storageKey }: {
  jobs: UseQueryResult<Job[], ApiRequestError>
  cancel: UseMutationResult<void, ApiRequestError, number>
  canCancel: boolean
  kindLabels: Record<string, string>
  stageLabels: Record<string, string>
  about: string
  emptyDescription: string
  storageKey?: string
}) {
  const { path } = useRouter()
  const cols = useColumnWidths(storageKey ?? `${path.split('/')[1] || 'collector'}-jobs-columns`, COLUMNS)
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
          <table className="w-full text-xs" style={cols.tableStyle}>
            <ColGroup cols={cols} />
            <thead className="bg-surface text-[11px] tracking-wide text-text-secondary uppercase">
              <tr><ResizableHeader cols={cols} className="px-3 py-2" content={{ actions: <span className="sr-only">Действие</span> }} /></tr>
            </thead>
            <tbody>
              {jobs.data.map((j) => (
                <tr key={j.id} className="border-t border-grid align-top">
                  <td className="px-3 py-2 break-words text-text"><span className="font-mono text-text-secondary">#{j.id}</span> {kindLabels[j.kind] ?? j.kind}</td>
                  <td className="px-3 py-2 break-words text-text-secondary">{stageLabels[j.stage] ?? j.stage}</td>
                  <td className={cn('px-3 py-2', j.status === 'running' && 'text-focus-ring', j.status === 'done' && 'text-kind-accepted', j.status === 'failed' && 'text-kind-1', j.status === 'cancelled' && 'text-text-secondary')}>{STATUS_LABEL[j.status]}</td>
                  <td className="px-3 py-2">{j.status === 'running' && j.total ? <Progress job={j} total={j.total} /> : null}</td>
                  <td className="px-3 py-2 break-words text-text-secondary">{j.error ? <span className="text-kind-1">{j.error}</span> : j.message}</td>
                  <td className="px-3 py-2 break-words text-text-secondary">{new Date(j.started_at).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })} <span className="font-mono">{j.started_by}</span></td>
                  <td className="truncate px-3 py-2 text-right font-mono tabular-nums text-text-secondary">{duration(j)}</td>
                  <td className="px-3 py-2 text-right whitespace-nowrap">
                    {j.status === 'running' && j.cancel_requested && <span className="text-text-secondary">отменяется…</span>}
                    {/* И после просьбы об отмене: осиротевшую задачу (процесс перезапускался) флаг не остановит, снятие закроет её сразу. */}
                    {canCancel && j.status === 'running' && <Button variant="ghost" className="ml-2" onClick={() => cancel.mutate(j.id)} aria-label={`Снять задачу ${j.id}`}><XCircle size={13} aria-hidden />снять</Button>}
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
