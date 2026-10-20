/**
 * Типы раздела Threat Hunting. Зеркалят ответы бэкенда
 * (backend/api/modules/siem/routers/hunting): имена полей дословно, даты — ISO-строки.
 * Префикс API — /api/siem/hunting.
 */
import type { Job, ScheduleView } from '@/platform/collector/types'
import type { FindingStatus } from '@/platform/findings/types'

/** Модуль и область статусов платформы; ключ находки — `th:<id>`. */
export const TH_MODULE = 'siem_th'
export const TH_SCOPE = 1

// --- Библиотека хантов -------------------------------------------------------

/** Итог последнего запуска запроса или ханта в строке списка. */
export interface HuntLastRun {
  at: string | null
  status: HuntQueryStatus
}

export interface HuntListItem {
  id: number
  code: string
  name: string
  technique_id: string | null
  enabled: boolean
  queries: number
  last_run: HuntLastRun | null
  /** Находки со статусом платформы «новая». */
  new_findings: number
  updated_at: string
}

export interface HuntsFilters {
  enabled?: boolean
  technique?: string
  q?: string
}

/** Статус запроса в прогоне: ok | failed | skipped | aborted. */
export type HuntQueryStatus = 'ok' | 'failed' | 'skipped' | 'aborted'

export interface QueryView {
  id: number
  query_id: string
  position: number
  query: string
  /** Поля через запятую. */
  fields: string
  /** Подписи колонок через запятую, по одной на поле. */
  fields_label: string
  limit: number | null
  enabled: boolean
  last: { at: string | null; events: number; status: HuntQueryStatus } | null
  new_findings: number
}

/** Запись истории запусков запроса в карточке ханта (бэкенд: `RunView` библиотеки). */
export interface HuntRunEntry {
  id: number
  query_id: string
  status: HuntQueryStatus
  started_at: string | null
  duration_ms: number | null
  events: number
  error: string | null
  finding_id: number | null
}

/** Находка в карточке ханта (бэкенд: `FindingRow` библиотеки); не больше 50 свежих. */
export interface HuntFindingRow {
  id: number
  kind: 'nightly' | 'deep'
  query_id: string
  period_from: string
  period_to: string
  event_count: number
  created_at: string
  status: FindingStatus
}

export interface HuntView {
  id: number
  code: string
  name: string
  description: string
  technique_id: string | null
  enabled: boolean
  updated_at: string
  updated_by: string
  queries: QueryView[]
  /** Не больше 30 свежих записей. */
  runs: HuntRunEntry[]
  findings: HuntFindingRow[]
}

export interface QueryIn {
  query_id: string
  query: string
  fields: string
  fields_label?: string
  limit?: number | null
  enabled?: boolean
}

/** Тело создания и правки ханта; код при правке сервер не меняет. */
export interface HuntIn {
  code: string
  name: string
  description?: string
  technique_id?: string | null
  enabled?: boolean
  queries: QueryIn[]
}

export interface CheckQueryIn {
  query: string
  fields: string
}

export interface CheckQueryOut {
  ok: boolean
  message: string
}

/** Что сделает импорт с ханта из файла: new — создаст, revive — вернёт удалённый, changed — отличается от базы, same — совпадает. */
export type ImportAction = 'new' | 'changed' | 'same' | 'revive'

export interface ImportRow {
  code: string
  action: ImportAction
  changes: string[]
}

export interface ImportPreview {
  rows: ImportRow[]
  hunts: number
}

export interface ImportApplyIn {
  file: File
  /** Коды изменённых хантов, которые заменить; остальные изменённые пропускаются. */
  replace: string[]
}

export interface ImportResult {
  created: number
  replaced: number
  skipped: number
}

// --- Настройки ---------------------------------------------------------------

export interface ThSettings {
  nightly_enabled: boolean
  /** Время старта ночного прогона, ЧЧ:ММ по поясу сервера; конец окна сервер выводит сам. */
  window_from: string
  /** Пауза между хантами ночного прогона; запросы одного ханта идут подряд. */
  hunt_pause_s: number
  request_timeout_s: number
  /** Пауза в минутах перед каждым повтором упавшего запроса; длина списка — число повторов. */
  retry_minutes: number[]
  nightly_deadline_h: number
  default_limit: number
  hot_days: number
  slice_hours: number
  slice_pause_s: number
  default_depth_months: number
  retention_days: number
}

export interface ThSettingsView extends ThSettings {
  schedule: ScheduleView | null
}

// --- Планировщик -------------------------------------------------------------

/** Строка очереди ночного прогона: хант в порядке `position`. */
export interface QueueRow {
  id: number
  code: string
  name: string
  technique_id: string | null
  /** «В очереди»: выключенный хант ночью пропускается, но место в порядке сохраняет. */
  enabled: boolean
  queries: number
  last_run: HuntLastRun | null
  position: number
}

/** `GET /scheduler`: расписание и очередь одним ответом. `next_run_at` пуст, пока расписание не сохранялось. */
export interface SchedulerOut {
  nightly_enabled: boolean
  window_from: string
  hunt_pause_s: number
  next_run_at: string | null
  /** Пояс сервера (`STOOLS_TZ`): в нём задано время старта. */
  tz: string
  hunts: QueueRow[]
}

export interface SchedulerIn {
  nightly_enabled: boolean
  window_from: string
  hunt_pause_s: number
}

/** `PUT /scheduler/order`: полный список id хантов в новом порядке; иной набор — 422. */
export interface OrderIn {
  ids: number[]
}

// --- Находки -----------------------------------------------------------------

export interface ThFindingListItem {
  id: number
  hunt_code: string
  hunt_name: string
  query_id: string
  /** Дата ночи; у находки большого ханта — null. */
  target_date: string | null
  period_from: string
  period_to: string
  event_count: number
  limit_hit: boolean
  created_at: string
  status: FindingStatus
  assignee: string | null
  due_date: string | null
  overdue: boolean
}

export type ThFindingSort = 'created_at' | 'night' | 'hunt' | 'query' | 'events' | 'status'

export interface ThFindingsFilters {
  /** Не задан — открытые; 'all' — любые. */
  status?: FindingStatus[] | 'all'
  hunt?: string[]
  date_from?: string
  date_to?: string
  limit_hit?: boolean
  sort?: ThFindingSort
  order?: 'asc' | 'desc'
  limit?: number
  offset?: number
}

export interface ThFindingList {
  total: number
  items: ThFindingListItem[]
  /** Счётчики фасета считаются без его собственного фильтра: `status` по всем статусам, `hunt` по кодам. */
  facets: { status: Record<string, number>; hunt: Record<string, number> }
}

export interface ThColumn {
  field: string
  label: string
}

/** Шапка статуса платформы в карточке; история и комментарии — `GET /api/findings/state`. */
export interface ThStateBrief {
  status: FindingStatus
  status_title: string
  assignee: string | null
  due_date: string | null
  overdue: boolean
  risk_until: string | null
  updated_by: string
  updated_at: string | null
}

export interface ThFindingView extends ThFindingListItem {
  /** Ключ в платформе статусов: `th:<id>`. */
  key: string
  kind: 'nightly' | 'deep'
  columns: ThColumn[]
  /** События удалены по сроку хранения, находка осталась. */
  events_purged: boolean
  run_id: number | null
  deep_id: number | null
  /** Большой хант отменён или ещё идёт: события собраны не за весь период. */
  partial: boolean
  /** Только у находки большого ханта: окна, где запрос упёрся в предел. */
  limit_hit_slices: number | null
  state: ThStateBrief
}

/** Страница событий: строка — значения в порядке `columns` находки. */
export interface EventsPage {
  total: number
  rows: unknown[][]
}

// --- Ночные прогоны ----------------------------------------------------------

/** queued | running | done | failed | aborted | cancelled | superseded. */
export type RunStatus = 'queued' | 'running' | 'done' | 'failed' | 'aborted' | 'cancelled' | 'superseded'

/** Ночной прогон за дату (бэкенд: `RunRow`). */
export interface RunView {
  id: number
  target_date: string
  period_from: string
  period_to: string
  status: RunStatus
  started_at: string | null
  finished_at: string | null
  queries_total: number
  queries_done: number
  findings: number
  /** Запросов с итогом `failed`. */
  errors: number
  error: string | null
  job_id: number | null
}

export interface RunQueryView {
  id: number
  query_pk: number
  hunt_code: string
  query_id: string
  status: HuntQueryStatus
  started_at: string | null
  duration_ms: number | null
  events: number
  error: string | null
  finding_id: number | null
}

export interface RunDetail extends RunView {
  queries: RunQueryView[]
}

/** `job_id` пуст, пока раздел занят другой задачей: прогон дождётся её конца. */
export interface RerunOut {
  run_id: number
  job_id: number | null
}

/** «Запустить за дату» для ночи без прогона (`POST /runs/rerun-date`). */
export interface RerunDateIn {
  target_date: string
}

/** Ночи, за которые прогон должен быть (`GET /runs/expected`): последнюю считает сервер по своему поясу. */
export interface ExpectedNights {
  from: string
  to: string
}

// --- Большие ханты -----------------------------------------------------------

/** queued | running | paused | done | failed | cancelled. */
export type DeepStatus = 'queued' | 'running' | 'paused' | 'done' | 'failed' | 'cancelled'

/** Состояния, в которых большой хант ещё идёт: список обновляется опросом. */
export const DEEP_ACTIVE: DeepStatus[] = ['queued', 'running', 'paused']

export interface DeepSource {
  hunt_code: string
  query_id: string | null
}

export interface DeepView {
  id: number
  title: string
  /** Откуда взят запрос; свой запрос — null. */
  source: DeepSource | null
  period_from: string
  period_to: string
  status: DeepStatus
  slices_done: number
  slices_total: number
  events: number
  finding_id: number | null
  /** Статус платформы у находки ханта; находки ещё нет — null. */
  status_state: FindingStatus | null
  job_id: number | null
  created_by: string
  created_at: string
}

export interface DeepDetail extends DeepView {
  query: string
  fields: string[]
  labels: string[]
  limit: number
  limit_hit_slices: number
  partial: boolean
  error: string | null
  finished_at: string | null
  finding: ThFindingView | null
}

/**
 * Запуск большого ханта: либо `hunt_query_id` (копия запроса библиотеки, присланные поля поверх),
 * либо `query` + `fields`. Период — `period_from` и `period_to` вместе либо `months` назад от сейчас.
 */
export interface DeepCreate {
  title?: string
  hunt_query_id?: number
  query?: string
  fields?: string
  fields_label?: string
  limit?: number
  months?: number
  period_from?: string
  period_to?: string
}

export interface DeepSaveIn {
  code: string
  name: string
}

// --- Задачи раздела ----------------------------------------------------------

/** Задача раздела (`kind`: nightly | deep). Отмена — через прогон или большой хант, у задачи её нет. */
export type ThJob = Job
