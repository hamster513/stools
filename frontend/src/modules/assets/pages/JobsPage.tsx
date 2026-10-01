import { useCancelJob, useJobs } from '@/modules/assets/api/queries'
import { JOB_KIND_LABELS, STAGE_LABELS } from '@/modules/assets/api/types'
import { useCan } from '@/lib/can'
import { CollectorJobsPage } from '@/platform/collector/JobsPage'

export function JobsPage() {
  // Ход задач аудитор видит целиком; останавливает их тот, кто запускает.
  const { write } = useCan()
  const jobs = useJobs()
  const cancel = useCancelJob()
  return (
    <CollectorJobsPage
      jobs={jobs}
      cancel={cancel}
      canCancel={write}
      kindLabels={JOB_KIND_LABELS}
      stageLabels={STAGE_LABELS}
      about="Сканы сетей, обновления DNS и синхронизация с модулями идут в фоне — вручную или по расписанию; идущие — сверху."
      emptyDescription="Задачи появятся после первого скана сети, обновления DNS или синхронизации."
    />
  )
}
