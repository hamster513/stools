/** Типы API модуля Assets. */

export { STAGE_LABELS } from '@/platform/collector/types'
export type { Job, JobStatus } from '@/platform/collector/types'

export const JOB_KIND_LABELS: Record<string, string> = {
  scan: 'Скан сети',
  dns: 'Обновление DNS',
  sync: 'Синхронизация с модулями',
}
