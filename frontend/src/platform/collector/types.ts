/**
 * Общие типы модулей-сборщиков (AD, KSC): у обоих есть подключения, снапшоты,
 * фоновые задачи и находки с фасетами. Поля, которые различаются, модули
 * добавляют в своих api/types.ts.
 */

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info'
export const SEVERITIES: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Info']
export const SEVERITY_LABELS: Record<Severity, string> = {
  Critical: 'критический',
  High: 'высокий',
  Medium: 'средний',
  Low: 'низкий',
  Info: 'справочно',
}

/** Цвет текста severity — те же токены, что шкала риска VM. */
export const SEVERITY_TEXT: Record<Severity, string> = {
  Critical: 'text-risk-critical',
  High: 'text-risk-high',
  Medium: 'text-risk-medium',
  Low: 'text-risk-low',
  Info: 'text-text-secondary',
}

export type FindingStatus = 'new' | 'persisting' | 'accepted' | 'fixed'
export const STATUS_LABELS: Record<FindingStatus, string> = {
  new: 'новая',
  persisting: 'висит',
  accepted: 'принята',
  fixed: 'закрыта',
}

/** Сравнение снапшота с предыдущим по времени сбора. */
export interface ComparedTo {
  previous_id: number | null
  collected_at: string | null
  new: number
  fixed: number
}

export interface SnapshotBase {
  id: number
  collected_at: string
  imported_at: string
  source: string
  collector: string
  filename: string
  findings: number
  by_severity: Record<Severity, number>
  new: number | null
  fixed: number | null
  previous_id: number | null
}

export interface CheckSummary {
  code: string
  title: string
  description: string
  total: number
  by_severity: Record<Severity, number>
  new: number
  fixed: number
  accepted: number
}

/** Обзор: в snapshot модуль добавляет свой счётчик (объекты, хосты). */
export interface OverviewBase {
  snapshot: {
    id: number
    collected_at: string
    source: string
    collector: string
    findings: number
    by_severity: Record<Severity, number>
  } | null
  compared_to?: ComparedTo
  accepted_total?: number
  checks: CheckSummary[]
}

export interface FindingBase {
  id: number
  key: string
  check: string
  check_title: string
  severity: Severity
  severity_original: Severity
  target: string
  allowlisted: boolean
  status: FindingStatus
  details: Record<string, unknown>
}

export interface FindingsResponse<F extends FindingBase> {
  total: number
  items: F[]
  facets: {
    check: Record<string, number>
    severity: Record<Severity, number>
    status: Record<FindingStatus, number>
    allowlisted: Record<'yes' | 'no', number>
  } | null
  compared_to: ComparedTo
  check_titles: Record<string, string>
}

export type FindingDetail<F extends FindingBase> = F & {
  description: string
  history: { snapshot_id: number; collected_at: string }[]
  verdict: { status: string; reason: string; decided_by: string; decided_at: string } | null
}

export interface FindingsQuery {
  check?: string
  severity?: Severity
  status?: FindingStatus
  allowlisted?: boolean
  q?: string
  limit?: number
  offset?: number
}

/** Поля страницы находок, которые попадают в фасеты. */
export type FindingFilters = Pick<FindingsQuery, 'check' | 'severity' | 'status' | 'allowlisted'>

export type JobStatus = 'running' | 'done' | 'failed' | 'cancelled'

export interface Job {
  id: number
  kind: string
  stage: string
  status: JobStatus
  progress: number
  processed: number
  total: number | null
  message: string
  error: string | null
  cancel_requested: boolean
  started_at: string
  finished_at: string | null
  started_by: string
}

export const STAGE_LABELS: Record<string, string> = {
  pending: 'ожидание',
  connecting: 'подключение',
  collecting: 'сбор',
  parsing: 'разбор',
  analyzing: 'проверки',
  persisting: 'запись',
  done: 'готово',
}
