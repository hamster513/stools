/** Типы API модуля Assets. */
import type { ScheduleView } from '@/platform/collector/types'
import type { FindingChange, FindingStatus } from '@/platform/findings/types'

export { STAGE_LABELS } from '@/platform/collector/types'
export type { Job, JobStatus, ScheduleIn } from '@/platform/collector/types'

export const JOB_KIND_LABELS: Record<string, string> = {
  scan: 'Скан сети',
  dns: 'Обновление DNS',
  sync: 'Синхронизация с модулями',
}

export type AssetSource = 'vm' | 'ksc' | 'ad' | 'scan' | 'dns'
export const SOURCES: AssetSource[] = ['vm', 'ksc', 'ad', 'scan', 'dns']
export const SOURCE_LABELS: Record<AssetSource, string> = {
  vm: 'VM',
  ksc: 'KSC',
  ad: 'AD',
  scan: 'Скан',
  dns: 'DNS',
}

export type DiscrepancyCode = 'stale' | 'conflict' | 'no_av' | 'ad_inactive' | 'unreachable' | 'unknown_host' | 'dns_orphan' | 'no_network'
export const CODES: DiscrepancyCode[] = ['stale', 'conflict', 'no_av', 'ad_inactive', 'unreachable', 'unknown_host', 'dns_orphan', 'no_network']
export const CODE_LABELS: Record<DiscrepancyCode, string> = {
  stale: 'данные устарели',
  conflict: 'источники расходятся',
  no_av: 'нет агента антивируса',
  ad_inactive: 'неактивный компьютер AD',
  unreachable: 'не отвечает',
  unknown_host: 'только сканер',
  dns_orphan: 'запись DNS без хоста',
  no_network: 'сеть не описана',
}
/** Фильтр списка: код расхождения или `any` — хоть одно расхождение. */
export type CodeFilter = DiscrepancyCode | 'any'
export const ANY_CODE_LABEL = 'любое расхождение'
/** Подсветка ячейки в таблице источников: те же токены, что у видов находок. */
export const MARK_TEXT: Record<'stale' | 'conflict', string> = {
  stale: 'text-kind-1',
  conflict: 'text-kind-2',
}

export type Criticality = 'Critical' | 'High' | 'Medium' | 'Low'
export const CRITICALITIES: Criticality[] = ['Critical', 'High', 'Medium', 'Low']
export const CRITICALITY_LABELS: Record<Criticality | 'none', string> = {
  Critical: 'критическая',
  High: 'высокая',
  Medium: 'средняя',
  Low: 'низкая',
  none: 'не задана',
}

export type PinnableField = 'name' | 'fqdn' | 'domain' | 'ip' | 'os'

export interface AssetSourceBadge {
  source: AssetSource
  /** Источник видит хост сейчас. */
  live: boolean
  /** Видит и видел недавно (моложе порога устаревания). */
  fresh: boolean
  seen_at: string
}

export interface AssetNetwork {
  id: number
  cidr: string
  title: string
  zone: string | null
}

export interface AssetItem {
  id: number
  name: string
  fqdn: string
  domain: string
  ip: string
  os: string
  network: AssetNetwork | null
  first_seen: string | null
  last_seen: string | null
  criticality: Criticality | ''
  tags: string[]
  pinned: Partial<Record<PinnableField, boolean>>
  sources: AssetSourceBadge[]
  discrepancy_count: number
  codes: DiscrepancyCode[]
}

export interface AssetsFacets {
  source: Record<AssetSource, number>
  /** Активы с расхождением кода под статусами фильтра (без фильтра — учитываемые в подсчётах). */
  code: Record<CodeFilter, number>
  zone: Record<string, number>
  criticality: Record<Criticality | 'none', number>
  /** Расхождения по статусам — без фильтра статуса. */
  disc_status: Record<FindingStatus, number>
  /** Просроченные расхождения — без фильтра статуса и срока. */
  disc_overdue: number
}

export interface AssetsResponse {
  total: number
  items: AssetItem[]
  facets: AssetsFacets | null
}

export interface AssetsQuery {
  q?: string
  source_has?: AssetSource
  source_missing?: AssetSource
  code?: CodeFilter
  network_id?: number
  zone?: string
  port?: number
  tag?: string
  criticality?: Criticality | 'none'
  /** Статусы расхождений через запятую или `all`; без него — учитываемые в подсчётах. */
  disc_status?: string
  /** Исполнитель расхождения: `me`, `none` или логин. */
  assignee?: string
  overdue?: boolean
}

export interface Observation {
  id: number
  source: AssetSource
  source_key: string
  name: string
  fqdn: string
  domain: string
  ip: string
  ips: string[]
  os: string
  seen_at: string | null
  gone_at: string | null
  extra: Record<string, unknown>
  /** Поле → stale | conflict: какие ячейки подсветить. */
  marks: Partial<Record<'name' | 'fqdn' | 'ip', 'stale' | 'conflict'>>
}

/** Расхождение карточки — находка статусов платформы (module `assets`, scope 0, `key`). */
export interface Discrepancy {
  code: DiscrepancyCode
  source: AssetSource | ''
  field: string
  value: string
  current: string
  text: string
  key: string
  status: FindingStatus
  status_title: string
  assignee: string | null
  due_date: string | null
  overdue: boolean
  risk_until: string | null
  /** Входит ли статус в подсчёты (настройка платформы `counted`). */
  counted: boolean
}

/** Массовая смена статуса расхождения `code` у отмеченных активов. */
export interface DiscrepancyBulk {
  ids: number[]
  code: DiscrepancyCode
  change: FindingChange
}

export interface AssetLinks {
  ad_finding_count: number | null
  ad_domain_id: number | null
  ad_query: string | null
  ksc_host_id: string | null
  ksc_server_id: number | null
  vm_host_id: number | null
  vm_cve_count: number | null
}

export interface AssetDetail extends AssetItem {
  network_manual: boolean
  note: string
  merged_into: number | null
  created_at: string | null
  updated_at: string | null
  observations: Observation[]
  discrepancies: Discrepancy[]
  links: AssetLinks
}

export interface AssetPatch {
  criticality?: Criticality | ''
  tags?: string[]
  note?: string
  /** Сеть вручную; null вместе с network_manual: false — вернуть расчёт по адресу. */
  network_id?: number | null
  network_manual?: boolean
}

/** Массовое изменение: теги добавляются и снимаются, не переданная критичность не меняется. */
export interface BulkPatch {
  ids: number[]
  criticality?: Criticality | ''
  tags_add?: string[]
  tags_remove?: string[]
}

/** Сеть /24 (IPv6 — /64) вокруг адреса: то, что предлагается создать для актива без сети. */
export function defaultCidr(ip: string): string {
  const v4 = ip.split('.')
  return v4.length === 4 ? `${v4.slice(0, 3).join('.')}.0/24` : `${ip}/64`
}

export const DEFAULT_PORTS = [22, 80, 135, 139, 443, 445, 3389]

/** «≈ N мин» из `estimated_seconds` API (минуты вверх, не меньше одной); null — сеть сканеру не по силам. */
export function scanEstimate(seconds: number | null): string {
  return seconds === null ? '—' : `≈ ${Math.max(1, Math.ceil(seconds / 60))} мин`
}

/** Поля сети, которые задаёт человек. */
export interface NetworkIn {
  cidr: string
  title: string
  description: string
  zone: string | null
  site: string
  owner: string
  vlan: number | null
  tags: string[]
  scan_enabled: boolean
  ports: number[]
  exclude: string[]
  concurrency: number
  icmp_timeout_ms: number
  tcp_timeout_ms: number
  /** Новых сокетов (ICMP echo или SYN) в секунду на весь скан, 10–5000. */
  rate_per_s: number
}

/** Расписание сканов сети — общее расписание планировщика (platform/collector). */
export type NetworkSchedule = ScheduleView

export interface ScanStarted {
  job_id: number
  /** false — ICMP-сокет не открывается, скан идёт в режиме «только порты». */
  icmp: boolean
}

export interface Network extends NetworkIn {
  id: number
  schedule_id: number | null
  schedule: NetworkSchedule | null
  last_scan_at: string | null
  last_scan_alive: number | null
  /** false — последний скан шёл в режиме «только порты»; null — сеть не сканировали. */
  last_scan_icmp: boolean | null
  /** Секунд на скан, если никто не ответит; null — сеть сканеру не по силам. */
  estimated_seconds: number | null
  created_at: string
  updated_at: string
  stats: {
    assets: number
    /** Живых при последнем скане; null — сеть ещё не сканировали. */
    alive_last_scan: number | null
    unknown_hosts: number
  }
}

export interface Zone {
  name: string
  title: string
  description: string
  /** Сколько сетей ссылается на зону: пока не ноль, удалить её нельзя. */
  networks: number
}

export type ZoneIn = Omit<Zone, 'networks'>

export type DnsMode = 'direct' | 'ad'

/** DNS-сервер: прямые и обратные запросы (`direct`) или чтение зон AD через подключение AD (`ad`). */
export interface DnsIn {
  title: string
  mode: DnsMode
  /** Имя или адрес сервера; пусто — системный резолвер. */
  server: string
  ad_connection_id: number | null
  zones: string[]
  forward: boolean
  reverse: boolean
  zone_read: boolean
  rate_per_s: number
  timeout_ms: number
  enabled: boolean
}

export interface DnsServer extends DnsIn {
  id: number
  schedule_id: number | null
  last_run_at: string | null
  schedule: NetworkSchedule | null
}

/** Подключение AD из `/api/ad/connections` — то, что нужно для выбора в форме DNS. */
export interface AdConnectionRef {
  id: number
  title: string
  host: string
}

/** Пороги расхождений и автосинхронизация после импорта модулей. */
export interface AssetSettings {
  /** Компьютер AD без входа и без других источников дольше — «неактивный». */
  inactive_days: number
  /** Наблюдение старше опорного на столько дней — «данные устарели». */
  stale_days: number
  sync_after_import: boolean
}

export type SyncSource = 'vm' | 'ksc' | 'ad'

/** `GET /sync/status`: последняя синхронизация и что лежит по каждому источнику модулей. */
export interface SyncStatus {
  last_sync_at: string | null
  last_job_id: number | null
  running_job_id: number | null
  sources: Record<string, { live: number; gone: number; seen_at: string | null }>
}

export interface AssetsOverview {
  assets_total: number
  /** Ключ "" — активы без сети или в сети без зоны. */
  by_zone: Record<string, number>
  by_source: Record<AssetSource, number>
  codes: Record<CodeFilter, number>
  networks: { total: number; scanned: number; no_network_assets: number }
  last_scans: { network_id: number; cidr: string; title: string; last_scan_at: string | null; last_scan_alive: number | null }[]
  last_dns: { dns_id: number; title: string; last_run_at: string | null }[]
  sync: { last_sync_at: string | null; running_job_id: number | null }
}
