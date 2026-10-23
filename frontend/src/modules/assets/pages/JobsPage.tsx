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
      about="Обновления DNS, проходы RackTables и синхронизация с модулями идут в фоне — вручную или по расписанию; идущие — сверху."
      emptyDescription="Задачи появятся после первого обновления DNS, прохода RackTables или синхронизации."
    />
  )
}
