import { X } from 'lucide-react'
import { errorText } from '@/api/client'
import { STAGE_LABELS, type Job } from '@/modules/vm/api/types'
import { Spinner } from '@/components/ui/Spinner'
import { cn } from '@/lib/cn'
import { Link } from '@/lib/router'
import type { HarborSyncState } from './useHarborSync'

/** Что сказать о задаче: ход стадией и сообщением, итог — готово / остановлена / ошибка. */
function jobText(job: Job): string {
  const withMessage = (head: string, message: string | null | undefined) => (message ? `${head}: ${message}` : head)
  if (job.status === 'running') return [STAGE_LABELS[job.stage] ?? job.stage, job.message].filter(Boolean).join(' · ')
  if (job.status === 'done') return withMessage('готово', job.message)
  if (job.status === 'cancelled') return withMessage('остановлена', job.message)
  return withMessage('ошибка', job.error ?? job.message)
}

/** Строка состояния синхронизации Harbor: запуск не удался, ход и итог задачи, ссылка «Задачи», «Скрыть». */
export function HarborSyncStatus({ state, className }: { state: HarborSyncState; className?: string }) {
  const { sync, job, running, dismiss } = state
  if (!job.data && !sync.error && !job.isError) return null
  const text = job.data && !job.isError ? jobText(job.data) : null
  return (
    <div className={cn('flex items-center gap-3 text-[11px] text-text-secondary', className)} role="status">
      {sync.error && !job.data && <span className="text-kind-1">Синхронизация не запущена: {errorText(sync.error, 'ошибка запроса')}</span>}
      {job.isError && <span className="text-kind-1">Не удалось получить состояние задачи: {errorText(job.error, 'ошибка запроса')}</span>}
      {job.data && text !== null && (
        <>
          {running && <Spinner size={12} />}
          <span className="text-text">Синхронизация Harbor, задача #{job.data.id}{text && ':'}</span>
          {text && <span className={cn('min-w-0 truncate', job.data.status === 'failed' && 'text-kind-1')} title={text}>{text}</span>}
        </>
      )}
      {job.data && <Link to="/vm/jobs" className="shrink-0 underline underline-offset-2 hover:text-text">Задачи</Link>}
      {!running && (
        <button type="button" onClick={dismiss} aria-label="Скрыть" className="ml-auto text-text-secondary hover:text-text">
          <X size={12} aria-hidden />
        </button>
      )}
    </div>
  )
}
