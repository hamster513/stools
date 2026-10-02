/**
 * Статусы находок — общий механизм платформы (бэкенд: api/platform/findings).
 * Коды и названия — дословно из спеки §1; `resolved` и `reopened` ставит
 * только система, человек выбирает из MANUAL_STATUSES.
 */

export type FindingStatus = 'new' | 'in_work' | 'risk_accepted' | 'false_positive' | 'fixed' | 'resolved' | 'reopened'

export const STATUSES: FindingStatus[] = ['new', 'in_work', 'risk_accepted', 'false_positive', 'fixed', 'resolved', 'reopened']
export const MANUAL_STATUSES: FindingStatus[] = ['new', 'in_work', 'risk_accepted', 'false_positive', 'fixed']
export const OPEN_STATUSES: FindingStatus[] = ['new', 'in_work', 'fixed', 'reopened']
/** Без обоснования эти статусы сервер не примет. */
export const NEEDS_REASON: FindingStatus[] = ['risk_accepted', 'false_positive']

export const STATUS_TITLES: Record<FindingStatus, string> = {
  new: 'Новая',
  in_work: 'В работе',
  risk_accepted: 'Принят риск',
  false_positive: 'Ложное срабатывание',
  fixed: 'Исправлено',
  resolved: 'Устранена',
  reopened: 'Переоткрыта',
}

export type FindingEventKind = 'status' | 'assign' | 'due' | 'comment' | 'auto_resolved' | 'auto_reopened' | 'risk_expired' | 'migrated'

export interface FindingEvent {
  at: string
  /** Логин или `system`. */
  actor: string
  kind: FindingEventKind
  from_status: FindingStatus | null
  to_status: FindingStatus | null
  comment: string
  details: Record<string, unknown>
}

/** Состояние одной находки; у находки без решения — `new` и пустые поля. */
export interface FindingState {
  module: string
  scope_id: number
  key: string
  status: FindingStatus
  status_title: string
  assignee: string | null
  assignee_name: string | null
  due_date: string | null
  overdue: boolean
  risk_until: string | null
  reason: string
  present: boolean
  first_seen_at: string | null
  updated_by: string
  updated_at: string | null
  events: FindingEvent[]
}

/** Тело смены: поле, которого нет, не трогается; `null` — очистить. */
export interface FindingChange {
  status?: FindingStatus
  assignee?: string | null
  due_date?: string | null
  risk_until?: string | null
  comment?: string
}

export interface FindingRef {
  module: string
  scope_id: number
  key: string
}

export interface BulkChangeRequest {
  module: string
  scope_id: number
  keys?: string[]
  filter?: Record<string, unknown>
  change: FindingChange
}

export interface DirectoryUser {
  login: string
  display_name: string | null
}

export interface FindingSettings {
  counted: Record<FindingStatus, boolean>
  risk_max_days: number | null
  risk_accept_role: 'analyst' | 'admin'
}

/** Счётчики области (`service.summary`): по статусам, просроченные, «риск истекает», без исполнителя. */
export interface FindingSummary {
  by_status: Record<FindingStatus, number>
  overdue: number
  risk_expiring: number
  unassigned: number
}

/** Строка «Моих находок» (`GET /api/findings/mine`): находки всех модулей, назначенные мне. */
export interface MyFinding {
  module: string
  module_title: string
  scope_id: number
  key: string
  title: string
  severity: string
  status: FindingStatus
  status_title: string
  due_date: string | null
  overdue: boolean
  risk_until: string | null
  present: boolean
  first_seen_at: string | null
  updated_at: string
  /** Путь карточки находки в интерфейсе модуля. */
  link: string
}

/** Значок меню: мои открытые находки и сколько из них просрочено. */
export interface MyFindingsCount {
  open: number
  overdue: number
}
