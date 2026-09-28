import { useAttackJobs, useCancelAttackJob } from '@/modules/attack/api/queries'
import { JOB_KIND_LABELS, JOB_STAGE_LABELS } from '@/modules/attack/api/types'
import { useCan } from '@/lib/can'
import { CollectorJobsPage } from '@/platform/collector/JobsPage'

export function JobsPage() {
  // Ход задач видят все; останавливает их тот, кто запускает, — администратор.
  const { admin } = useCan()
  const jobs = useAttackJobs()
  const cancel = useCancelAttackJob()
  return (
    <CollectorJobsPage
      jobs={jobs}
      cancel={cancel}
      canCancel={admin}
      kindLabels={JOB_KIND_LABELS}
      stageLabels={JOB_STAGE_LABELS}
      about="Перевод техник идёт в фоне и обращается к модели; идущие — сверху."
      emptyDescription="Перевод недостающего запускается в настройках модуля."
    />
  )
}
