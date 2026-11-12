export interface RetentionPolicy {
  receipt_payload_days: number
  collector_changes_days: number
  successful_jobs_days: number
  failed_jobs_days: number
  source_runs_days: number
  clear_staging: boolean
}

export type RetentionDays = Exclude<keyof RetentionPolicy, 'clear_staging'>
export const RETENTION_FIELDS: { key: RetentionDays; label: string; hint: string }[] = [
  { key: 'receipt_payload_days', label: 'События синхронизации в VM', hint: 'Полное содержимое событий; контрольные суммы повторной доставки сохраняются.' },
  { key: 'collector_changes_days', label: 'Журнал изменений коллектора', hint: 'Сокращается только при безопасном восстановлении синхронизации.' },
  { key: 'successful_jobs_days', label: 'Успешные служебные задания', hint: 'История завершённых заданий модулей и коллектора.' },
  { key: 'failed_jobs_days', label: 'Ошибки служебных заданий', hint: 'История ошибок для диагностики.' },
  { key: 'source_runs_days', label: 'История запусков источников', hint: 'Завершённые запуски источников коллектора.' },
]

export interface RetentionItem {
  id: string
  title: string
  eligible_rows: number | null
  protected_rows: number | null
  estimated_bytes: number | null
  status: string
  reason: string | null
  removed_rows?: number
  reclaimed_bytes?: number | null
}
export interface RetentionPreview {
  preview_id: string
  created_at: string
  expires_at: string
  items: RetentionItem[]
  warnings: string[]
}
export interface RetentionRun {
  status: string
  items: RetentionItem[]
  warnings: string[]
  started_at: string
  finished_at: string | null
}
export interface RetentionResponse { policy: RetentionPolicy; last_run: RetentionRun | null }

export function validRetentionPolicy(policy: RetentionPolicy): boolean {
  return RETENTION_FIELDS.every(({ key }) => Number.isInteger(policy[key]) && policy[key] >= 1 && policy[key] <= 3650)
}

export function canRunRetention(preview: RetentionPreview | null, dirty: boolean, busy: boolean, now: number): boolean {
  return !!preview && !dirty && !busy && Date.parse(preview.expires_at) > now
    && preview.items.some(item => item.status === 'ready' && ((item.eligible_rows ?? 0) > 0 || (item.estimated_bytes ?? 0) > 0))
}

export function retentionConfirmation(preview: RetentionPreview): string {
  const lines = preview.items.filter(item => item.status === 'ready').map(item =>
    `${item.title}: ${item.eligible_rows?.toLocaleString('ru-RU') ?? 'неизвестно'} записей; оценка данных: ${item.estimated_bytes?.toLocaleString('ru-RU') ?? 'неизвестно'} байт. Защищено: ${item.protected_rows?.toLocaleString('ru-RU') ?? 'неизвестно'}.`)
  return ['Выполнить очистку по этому расчёту?', ...lines, ...preview.warnings, 'Защищённые данные сохраняются. Размер файлов базы может не уменьшиться. Действие нельзя отменить.'].join('\n')
}
