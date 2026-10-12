/**
 * Общие типы модулей-сборщиков (AD, KSC): у обоих есть подключения, снапшоты,
 * фоновые задачи и находки с фасетами. Поля, которые различаются, модули
 * добавляют в своих api/types.ts. Статусы находок — общий механизм
 * платформы (platform/findings).
 */
import type { FindingFacetFilters } from '@/platform/findings/facets'
import type { FindingStatus, FindingSummary } from '@/platform/findings/types'

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

/** Появилась в этом снапшоте, была и раньше, нет в последнем снапшоте (данные — из прежнего). */
export type FindingDelta = 'new' | 'same' | 'gone'

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
  /** Находки со статусами, которые учитываются (настройка платформы); by_severity — по ним же. */
  total: number
  by_severity: Record<Severity, number>
  /** Все находки проверки в снапшоте. */
  all: number
  open: number
  /** Появились в этом снапшоте. */
  new: number
  /** Пропали с прошлого снапшота. */
  resolved: number
  /** Почему результат проверки не проверка: в выгрузке не было данных. */
  unchecked?: string | null
  /** Категория проверки и её название; у модулей без категорий (KSC) пустые. */
  category?: string
  category_title?: string
}

/** Порядок категорий на обзоре — как CATEGORIES в backend/api/modules/ad/core/checks/common.py. */
export const CATEGORY_ORDER = ['accounts', 'privileged', 'kerberos', 'acl', 'gpo', 'dc', 'domain', 'trust', 'pki']

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
  /** Учитываемые находки последнего снапшота; statuses — какие статусы учтены (фильтр ссылок с плиток). */
  counted?: { total: number; by_severity: Record<Severity, number>; statuses: FindingStatus[] }
  summary?: FindingSummary
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
  details: Record<string, unknown>
  status: FindingStatus
  status_title: string
  assignee: string | null
  assignee_name: string | null
  due_date: string | null
  overdue: boolean
  risk_until: string | null
  first_seen_at: string | null
  age_days: number | null
  delta: FindingDelta
}

export interface FindingsResponse<F extends FindingBase> {
  total: number
  items: F[]
  facets: {
    check: Record<string, number>
    severity: Record<Severity, number>
    allowlisted: Record<'yes' | 'no', number>
    delta: Record<FindingDelta, number>
    /** Считаются без фильтра статуса; assignee — без фильтра исполнителя, `none` — без исполнителя. */
    status: Record<FindingStatus, number>
    assignee: Record<string, number>
    flags: { overdue: number; risk_expiring: number }
  } | null
  compared_to: ComparedTo
  check_titles: Record<string, string>
  /** Смотрят последний снапшот области: только у него есть строки отсутствующих находок. */
  is_latest: boolean
  /** Статусы — на сегодня у любого снапшота, находки — на дату снапшота. */
  statuses_as_of: 'today'
}

export type FindingDetail<F extends FindingBase> = F & {
  description: string
  /** «Как исправить» и ссылки; есть у модулей с каталогом проверок (AD). */
  guidance?: { remediation: string; references: { title: string; url: string }[] }
  history: { snapshot_id: number; collected_at: string }[]
}

/** Параметры запроса списка: статус — коды через запятую или `all`; без него — открытые. */
export interface FindingsQuery {
  check?: string
  severity?: Severity
  allowlisted?: boolean
  delta?: FindingDelta
  status?: string
  assignee?: string
  overdue?: boolean
  risk_expiring?: boolean
  q?: string
  limit?: number
  offset?: number
}

/** Фильтры страницы находок, которые попадают в фасеты. */
export interface FindingFilters extends FindingFacetFilters {
  check?: string
  severity?: Severity
  allowlisted?: boolean
  delta?: FindingDelta
}

/** Расписание задачи планировщика (скан сети, DNS, синхронизация, сбор по подключению); окно — местное время пояса STOOLS_TZ (`tz`). */
export interface ScheduleView {
  id: number
  interval_hours: number
  window_from: string | null
  window_to: string | null
  enabled: boolean
  next_run_at: string | null
  last_run_at: string | null
  last_job_id: number | null
  tz: string
}

export interface ScheduleIn {
  interval_hours: number
  window_from: string | null
  window_to: string | null
  enabled: boolean
}

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
