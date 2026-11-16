export interface TaskRequest { module: string; kind: string; target_id: number; options?: Record<string, unknown> }
export interface Dependency { key: string; max_age_minutes: number }
export interface QueueTask extends TaskRequest {
  key: string; title: string; dependencies: Dependency[]; hidden_dependencies: number
  can_run: boolean; can_configure: boolean; dependency_allowed: boolean; last_updated_at?: string | null
}
export interface QueueStep extends TaskRequest {
  id: number; key: string; title: string; is_root: boolean; dependencies: Dependency[]
  status: string; message: string; job_id: number | null; checked_at: string | null
  started_at: string | null; finished_at: string | null; result: Record<string, unknown> | null
}
export interface QueueRun {
  id: number; actor: string; origin: string; status: string; cancel_requested: boolean
  created_at: string; started_at: string | null; finished_at: string | null; steps: QueueStep[]
}
export const STATUS: Record<string, string> = {
  queued: 'В очереди', waiting: 'Ожидает источник', starting: 'Запускается', running: 'Выполняется',
  done: 'Выполнено', fresh: 'Данные свежие', partial: 'Выполнено частично', failed: 'Ошибка',
  blocked: 'Зависимость не выполнена', cancelled: 'Отменено', skipped: 'Не потребовалось',
}
export const active = (status: string) => status === 'queued' || status === 'running'
export const taskKey = (task: TaskRequest) => `${task.module}/${task.kind}/${task.target_id}`
