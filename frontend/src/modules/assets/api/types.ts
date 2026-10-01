/** Типы API модуля Assets. */

export { STAGE_LABELS } from '@/platform/collector/types'
export type { Job, JobStatus } from '@/platform/collector/types'

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
  code: Record<DiscrepancyCode, number>
  zone: Record<string, number>
  criticality: Record<Criticality | 'none', number>
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
  code?: DiscrepancyCode
  network_id?: number
  zone?: string
  port?: number
  tag?: string
  criticality?: Criticality | 'none'
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

export interface Discrepancy {
  code: DiscrepancyCode
  source: AssetSource | ''
  field: string
  value: string
  current: string
  text: string
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

export const DEFAULT_PORTS = [22, 80, 135, 139, 443, 445, 3389]

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
}

/** Расписание сканов сети; окно — местное время пояса STOOLS_TZ (`tz`). */
export interface NetworkSchedule {
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
