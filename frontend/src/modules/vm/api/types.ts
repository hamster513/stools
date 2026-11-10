/**
 * Типы запросов и ответов API модуля Vulnerability Management.
 * Источник — спека §8 и роутеры backend/api/modules/vm/routers.
 */
import type { ScheduleView } from '@/platform/collector/types'
import type { FindingStatus, FindingSummary } from '@/platform/findings/types'

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical'

export const LEVEL_LABELS: Record<RiskLevel, string> = {
  low: 'низкий',
  medium: 'средний',
  high: 'высокий',
  critical: 'критический',
}

export const LEVELS: RiskLevel[] = ['critical', 'high', 'medium', 'low']

export type CvssSource = 'nvd_v3' | 'nvd_v2' | 'none'

export const CVSS_SOURCE_LABELS: Record<CvssSource, string> = {
  nvd_v3: 'NVD v3',
  nvd_v2: 'NVD v2',
  none: 'нет',
}

export interface VulnItem {
  /** Ключ пары в статусах находок: `hostname|ip|cve`. */
  key: string
  host_id: number
  hostname: string
  ip: string
  os_name: string
  criticality: string
  zone: string
  cve_id: string
  risk: number
  risk_raw: number
  /** По порогам настроек на момент чтения: клиент уровни из балла не выводит. */
  level: RiskLevel
  cvss: number | null
  cvss_source: CvssSource
  epss: number | null
  exploitdb_type: string | null
  exploits_count: number
  msf_rank: string | null
  msf_modules: number
  /** CVE в каталоге CISA KEV — эксплуатируется в реальных атаках. */
  kev: boolean
  kev_ransomware: boolean
  status: FindingStatus
  status_title: string
  assignee: string | null
  assignee_name: string | null
  due_date: string | null
  overdue: boolean
  risk_until: string | null
  /** Истории пар VM не хранит: возраст есть, только если его знает строка состояния. */
  first_seen_at: string | null
}

export interface VulnsFacets {
  level: Record<RiskLevel, number>
  criticality: Record<string, number>
  zone: Record<string, number>
  os: Record<string, number>
  exploits: Record<string, number>
  msf: Record<string, number>
  kev: Record<string, number>
  cvss_source: Record<string, number>
  status: Record<FindingStatus, number>
  /** Логин → число; `none` — без исполнителя. */
  assignee: Record<string, number>
  flags: { overdue: number; risk_expiring: number }
}

export interface VulnsResponse {
  /** Только у первой страницы (offset=0), как и фасеты. */
  total: number | null
  items: VulnItem[]
  facets: VulnsFacets | null
}

export type VulnSort =
  | 'risk_desc'
  | 'risk_asc'
  | 'cvss_desc'
  | 'epss_desc'
  | 'exploits_desc'
  | 'host_asc'
  | 'cve_asc'

export interface VulnsQuery {
  q?: string
  host?: string
  cve?: string
  /** Многозначные фасеты: в адресе — повторением ключа (buildQuery), в массовой смене — списком. */
  criticality?: string[]
  zone?: string[]
  os?: string[]
  level?: RiskLevel[]
  exploits?: boolean
  msf?: boolean
  kev?: boolean
  cvss_source?: CvssSource[]
  host_id?: number
  /** Коды (ключ повторяется) или `all`; не задан — открытые. */
  status?: string[] | 'all'
  /** `me`, `none` или логин; несколько — «ИЛИ». */
  assignee?: string[]
  overdue?: boolean
  risk_expiring?: boolean
  sort?: VulnSort
  limit?: number
  offset?: number
}

export interface Factor {
  value: number
  source: string
  substituted: boolean
}

export interface RiskCard {
  host: {
    id: number
    hostname: string
    ip: string
    os_name: string
    groups: string
    criticality: string
    zone: string
    zone_marked: boolean
    internet_access: boolean
    confidential_data: boolean
  }
  cve: {
    cve_id: string
    description: string | null
    published: string | null
    cvss: number | null
    cvss_source: CvssSource
    epss: number | null
    epss_percentile: number | null
    nvd_url: string
    kev: boolean
    /** Даты — `YYYY-MM-DD`; дата, вымогатели и срок CISA для человека, в балл не входят. */
    kev_added: string | null
    kev_ransomware: boolean
    kev_due: string | null
    exploits: { exploit_id: number; type: string; verified: boolean; published: string | null }[]
    msf_modules: { fullname: string; name: string; rank: number }[]
  }
  risk: {
    score: number
    raw: number
    level: RiskLevel
    level_word: string
    threshold: number
    /** L — вероятность эксплуатации. */
    likelihood: Factor
    likelihood_parts: { kev: Factor; epss: Factor; exploit: Factor; msf: Factor }
    /** S — тяжесть: CVSS ÷ 10 × достижимость. */
    severity: Factor
    severity_parts: { cvss: Factor; reach: Factor }
    /** V — ценность хоста. */
    value: Factor
    value_parts: { criticality: Factor; confidential: Factor; internet: Factor }
  }
  refs_loaded_at: Record<string, string | null>
}

export interface HostDetail {
  host: { id: number; hostname: string; ip: string; os_name: string; groups: string; criticality: string; zone: string }
  items: VulnItem[]
}

export interface RefOverview {
  name: string
  loaded_at: string | null
  records: number
  stale: boolean
}

export interface Overview {
  hosts: number
  /** Пары с учитываемым статусом (настройка платформы `counted`). */
  pairs: number
  /** Все пары последнего импорта. */
  pairs_all: number
  cves: number
  above_threshold: number
  threshold: number
  distribution: Record<RiskLevel, number>
  /** Пары с CVE из каталога CISA KEV, по учитываемым статусам. */
  kev_pairs: number
  findings: FindingSummary
  top_cves: { cve_id: string; hosts: number; risk_sum: number; risk_max: number; cvss: number | null; epss: number | null; exploitdb_type: string | null }[]
  top_hosts: { host_id: number; hostname: string; ip: string; zone: string; criticality: string; pairs: number; risk_sum: number; risk_max: number }[]
  data: {
    last_import: { finished_at: string; source: string; filename: string; hosts: number; pairs: number; cves: number } | null
    refs: RefOverview[]
    unmarked_zones: number
    cves_without_epss: number
    cves_without_nvd: number
  }
}

export interface Zone {
  name: string
  internet_access: boolean
  confidential_data: boolean
  marked: boolean
  hosts: number
}

/** Нижние границы уровней по баллу; ниже `medium` — низкий. Сервер требует 0 < medium < high < critical ≤ 100. */
export interface Levels {
  medium: number
  high: number
  critical: number
}

/** Веса формулы Risk = round(100 × L × S × V) (спека 2026-10-21 §9): все значения — доли 0..1, кроме уровней. */
export interface Weights {
  prior_epss: number
  cvss_missing: number
  reach_unknown: number
  p_exdb: Record<string, number>
  p_msf: Record<string, number>
  reach: { network_internet: number; network_internal: number; adjacent: number; local: number }
  value: { criticality: Record<string, number>; conf_bonus: number; inet_bonus: number }
  levels: Levels
}

export interface ConnectionView {
  host: string
  verify_tls: boolean
  os_exclude: string[]
  pdql_extra: string
  limit: number
  /** Персональный API-токен MaxPatrol задан; само значение наружу не отдаётся. */
  api_token_set: boolean
  configured: boolean
}

export interface SettingsView {
  connection: ConnectionView
  weights: Weights
  threshold: number
  attack_min_risk: number
  defaults: { weights: Weights; threshold: number; attack_min_risk: number }
}

export interface SettingsUpdate {
  connection: {
    host: string
    /** Пусто — оставить прежний токен. */
    api_token: string
    verify_tls: boolean
    os_exclude: string[]
    pdql_extra: string
    limit: number
  }
  weights: Weights
  threshold: number
  //: Необязательно: форма подключения про порог матрицы не знает, и
  //: пропущенное поле оставляет сохранённое значение, а не умолчание.
  attack_min_risk?: number
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

export const JOB_KIND_LABELS: Record<string, string> = {
  import_vm: 'Импорт из MaxPatrol VM',
  import_file: 'Импорт из файла',
  ref_epss: 'Справочник EPSS',
  ref_nvd: 'Справочник NVD',
  ref_exploitdb: 'Справочник ExploitDB',
  ref_msf: 'Справочник Metasploit',
  ref_kev: 'Справочник KEV',
  ref_bundle: 'Архив справочников',
  recalculate: 'Пересчёт риска',
  bulk_status: 'Массовая смена статусов',
  harbor_sync: 'Синхронизация Harbor',
  trends_sync: 'Получение трендов',
  trends_import: 'Импорт пакета трендов',
}

export const STAGE_LABELS: Record<string, string> = {
  pending: 'ожидание',
  receiving: 'получение публикаций',
  analyzing: 'анализ сигналов',
  listing: 'обход реестра',
  reports: 'чтение отчётов',
  fetching: 'экспорт из VM',
  parsing: 'разбор',
  writing: 'запись',
  enriching: 'обогащение',
  scoring: 'расчёт риска',
  downloading: 'скачивание',
  extracting: 'распаковка',
  loading: 'загрузка',
  cves: 'вероятность и тяжесть CVE',
  hosts: 'ценность хостов',
  pairs: 'риск пар',
  status: 'смена статусов',
  groups: 'локальные группы',
  docker: 'образы и контейнеры Docker',
  runtime: 'сопоставление образов с хостами',
  done: 'готово',
}

export interface ImportState {
  last: { id: number; finished_at: string; source: string; filename: string; hosts: number; pairs: number; cves: number; new_zones: number } | null
  active: Job | null
}

export interface RefState {
  name: string
  title: string
  url: string
  loaded_at: string | null
  source: 'network' | 'file' | 'bundle' | null
  records: number
  detail: string
  stale: boolean
  active_job_id: number | null
}

// ---- Образы контейнеров (Harbor) -------------------------------------------------

export type ImageScanStatus = 'success' | 'pending' | 'running' | 'error' | 'none'

export const SCAN_STATUS_LABELS: Record<ImageScanStatus, string> = {
  success: 'успешно',
  pending: 'ожидает',
  running: 'идёт',
  error: 'ошибка',
  none: 'не сканировался',
}

export const SCAN_STATUSES = Object.keys(SCAN_STATUS_LABELS) as ImageScanStatus[]

/** Оценка Trivy — нижним регистром, как её отдаёт API. */
export type TrivySeverity = 'critical' | 'high' | 'medium' | 'low' | 'unknown'

export const TRIVY_SEVERITIES: TrivySeverity[] = ['critical', 'high', 'medium', 'low', 'unknown']

export const TRIVY_SEVERITY_LABELS: Record<TrivySeverity, string> = {
  critical: 'критическая',
  high: 'высокая',
  medium: 'средняя',
  low: 'низкая',
  unknown: 'неизвестная',
}

/** Уровень в фасетах и фильтрах образов и их находок: `none` — риска нет. */
export type ImageLevel = RiskLevel | 'none'

export const IMAGE_LEVELS: ImageLevel[] = [...LEVELS, 'none']

export const IMAGE_LEVEL_LABELS: Record<ImageLevel, string> = { ...LEVEL_LABELS, none: 'нет оценки' }

/** Подсказка к «—» вместо риска образа: почему балла нет. */
export const NO_RISK_TITLE = 'нет оценённых пар: образ не сканировался, в отчёте нет CVE или строки витрины нет. Если справочники (NVD, EPSS, KEV) не загружены, риск показывается как 0, а не «—»'

export interface ImageItem {
  id: number
  project: string
  repository: string
  /** `project/repository`. */
  name: string
  /** Платформы мультиархитектурного индекса через «, ». */
  platform: string | null
  tags: string[]
  digest_short: string
  digest: string
  /** Байты. */
  size: number | null
  pushed_at: string | null
  scan_status: ImageScanStatus
  scanned_at: string | null
  scanner: string | null
  trivy: Record<TrivySeverity | 'total', number>
  /** Наибольший риск пар образа; null — оценённых пар нет. */
  risk_max: number | null
  level: RiskLevel | null
  cves_scored: number
  /** Почему образ не обновлён в последней синхронизации. */
  sync_error: string | null
  /** Уникальные хосты с running-контейнерами; null — нет снимка или сопоставления. */
  running_host_count?: number | null
  runtime_state?: 'ready' | 'mapping_missing' | 'snapshot_missing'
}

/** Карточка образа: элемент списка и время последней синхронизации. */
export interface ImageDetail extends ImageItem {
  last_sync_at: string | null
}

export interface ImagesFacets {
  project: Record<string, number>
  scan_status: Partial<Record<ImageScanStatus, number>>
  level: Record<ImageLevel, number>
}

export interface ImagesResponse {
  /** Только у первой страницы (offset=0), как и фасеты. */
  total: number | null
  items: ImageItem[]
  facets: ImagesFacets | null
}

export type ImageSort = 'risk_desc' | 'name' | 'pushed_desc' | 'trivy_desc'

export interface ImagesQuery {
  q?: string
  project?: string[]
  scan_status?: ImageScanStatus[]
  level?: ImageLevel[]
  /** Есть хотя бы одна находка такой оценки Trivy. */
  trivy?: ('critical' | 'high')[]
  /** Есть подтверждённый запущенный контейнер в последнем снимке MaxPatrol VM. */
  running_only?: boolean
  sort?: ImageSort
  limit?: number
  offset?: number
}

export interface ImageVulnItem {
  /** Идентификатор из отчёта как есть: CVE-…, GHSA-…, TEMP-… */
  cve_id: string
  package: string
  installed_version: string
  fixed_version: string | null
  trivy_severity: TrivySeverity
  trivy_cvss: number | null
  risk: number | null
  level: RiskLevel | null
  epss: number | null
  /** null — идентификатора нет в витрине CVE. */
  kev: boolean | null
  cvss: number | null
  cvss_source: CvssSource | null
  description: string | null
  link: string | null
  is_cve: boolean
}

export interface ImageVulnsFacets {
  severity: Partial<Record<TrivySeverity, number>>
  level: Record<ImageLevel, number>
  fixed: { yes: number; no: number }
}

export interface ImageVulnsResponse {
  total: number | null
  items: ImageVulnItem[]
  facets: ImageVulnsFacets | null
}

export type ImageVulnSort = 'risk_desc' | 'severity_desc' | 'package' | 'cve'

export interface ImageVulnsQuery {
  q?: string
  severity?: TrivySeverity[]
  level?: ImageLevel[]
  fixed?: 'yes' | 'no'
  sort?: ImageVulnSort
  limit?: number
  offset?: number
}

/** Находка образа и расчёт её риска; `factors` — null для не-CVE и CVE вне витрины. */
export interface ImageRiskCard {
  image: ImageItem
  vuln: ImageVulnItem
  /** Те же L, S, V, что у пары хоста, с условиями образа: интернета, критичности и конфиденциальности нет. */
  factors: RiskCard['risk'] | null
  nvd_url: string | null
}

export interface HarborSyncError {
  target: string
  stage: 'repositories' | 'artifacts' | 'report' | 'unknown'
  reason: string | null
  http_status: number | null
  hint: string
}

export interface LastSyncView {
  finished_at: string
  images: number
  /** Пар образ–находка. */
  cves: number
  repositories: number
  /** Образы без готового скана. */
  skipped_unscanned: number
  /** `проект` или `проект/репозиторий`, не прочитанные в этой синхронизации. */
  errors: string[]
  error_details?: HarborSyncError[]
}

export interface HarborView {
  url: string
  robot_name: string
  /** Секрет робота задан; само значение наружу не отдаётся. */
  robot_secret_set: boolean
  verify_tls: boolean
  /** Пусто — все проекты, доступные роботу. */
  projects: string[]
  tags_per_repo: number
  /** Заданы адрес, имя и секрет робота. */
  configured: boolean
  last_sync: LastSyncView | null
  schedule: ScheduleView | null
}

export interface HarborUpdate {
  url: string
  robot_name: string
  /** Пусто — оставить прежний секрет; при смене адреса нужен новый (иначе 422). */
  robot_secret: string
  verify_tls: boolean
  projects: string[]
  /** 1..100. */
  tags_per_repo: number
}
