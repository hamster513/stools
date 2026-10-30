import { useState } from 'react'
import { useJob, useSyncHarbor } from '@/modules/vm/api/queries'

/**
 * Синхронизация Harbor «сейчас»: запуск (202 с номером задачи) и слежение за задачей.
 * Общая для страницы образов и блока в настройках; ход показывает `HarborSyncStatus`.
 */
export function useHarborSync() {
  const sync = useSyncHarbor()
  const [jobId, setJobId] = useState<number | undefined>(undefined)
  const job = useJob(jobId)
  // Не удалось узнать состояние задачи — кнопка не должна оставаться занятой навсегда.
  const running = !job.isError && job.data?.status === 'running' ? job.data : null
  // Между 202 и первым ответом о задаче кнопка тоже занята: второй запуск получил бы 409.
  const busy = sync.isPending || running !== null || (jobId !== undefined && !job.data && !job.isError)

  function start() {
    setJobId(undefined)
    sync.mutate(undefined, { onSuccess: (r) => setJobId(r.job_id) })
  }
  function dismiss() {
    setJobId(undefined)
    sync.reset()
  }
  return { sync, job, running, busy, start, dismiss }
}

export type HarborSyncState = ReturnType<typeof useHarborSync>
