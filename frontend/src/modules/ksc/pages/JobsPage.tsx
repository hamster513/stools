import { useCancelJob, useJobs } from '@/modules/ksc/api/queries'
import { JOB_KIND_LABELS, STAGE_LABELS } from '@/modules/ksc/api/types'
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
      about="Загрузка выгрузок, сбор из KSC и пересчёт идут в фоне; идущие — сверху."
      emptyDescription="Загрузите выгрузку или запустите сбор в настройках."
    />
  )
}
