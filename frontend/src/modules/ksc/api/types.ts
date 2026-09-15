/** Типы API модуля Kaspersky Security Center (docs/ksc/api.md, спека §7). */

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info'
export const SEVERITIES: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Info']
export const SEVERITY_LABELS: Record<Severity, string> = {
  Critical: 'критический',
  High: 'высокий',
  Medium: 'средний',
  Low: 'низкий',
  Info: 'справочно',
}

export type FindingStatus = 'new' | 'persisting' | 'accepted' | 'fixed'
export const STATUS_LABELS: Record<FindingStatus, string> = {
  new: 'новая',
  persisting: 'висит',
  accepted: 'принята',
  fixed: 'закрыта',
}

export interface Server {
  id: number
  name: string
  version: string
  snapshots: number
  last_snapshot_id: number | null
  last_snapshot_at: string | null
}

export interface Snapshot {
  id: number
  server_id: number
  collected_at: string
  imported_at: string
  source: 'file' | 'online'
  collector: string
  filename: string
  hosts: number
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

export interface Coverage {
  ad_total: number | null
  ksc_total: number
  both: number | null
  ad_only: number | null
  ksc_only: number | null
  with_agent: number
  with_protection: number
  protection_on: number
  bases_fresh: number
}

export interface Overview {
  server: { id: number; name: string; version: string }
  snapshot: {
    id: number
    collected_at: string
    source: string
    collector: string
    hosts: number
    findings: number
    by_severity: Record<Severity, number>
  } | null
  compared_to?: { previous_id: number | null; collected_at: string | null; new: number; fixed: number }
  accepted_total?: number
  coverage: Coverage | null
  checks: CheckSummary[]
}

export interface Finding {
  id: number
  key: string
  check: string
  check_title: string
  severity: Severity
  severity_original: Severity
  host: string
  target: string
  allowlisted: boolean
  status: FindingStatus
  details: Record<string, unknown>
}

export interface FindingsResponse {
  total: number
  items: Finding[]
  facets: {
    check: Record<string, number>
    severity: Record<Severity, number>
    status: Record<FindingStatus, number>
    allowlisted: Record<'yes' | 'no', number>
  } | null
  compared_to: { previous_id: number | null; collected_at: string | null; new: number; fixed: number }
  check_titles: Record<string, string>
}

export interface FindingDetail extends Finding {
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

export type HostAgent = 'none' | 'silent' | 'alive'
export type HostProtection = 'none' | 'off' | 'on'
export type HostBases = 'fresh' | 'old' | 'unknown'

export const AGENT_LABELS: Record<HostAgent, string> = {
  none: 'нет агента',
  silent: 'молчит',
  alive: 'на связи',
}

export const PROTECTION_LABELS: Record<HostProtection, string> = {
  none: 'нет защиты',
  off: 'выключена',
  on: 'работает',
}

export const BASES_LABELS: Record<HostBases, string> = {
  fresh: 'свежие',
  old: 'устарели',
  unknown: 'неизвестно',
}

export const IN_AD_LABELS: Record<string, string> = {
  both: 'в AD и KSC',
  ksc_only: 'только KSC',
}

export const RTP_STATE_LABELS: Record<number, string> = {
  0: 'неизвестно',
  1: 'остановлена',
  2: 'приостановлена',
  3: 'запускается',
  9: 'сбой',
  10: 'не установлена',
  11: 'не поддерживается лицензией',
}

export interface Host {
  id: number
  host_id: string
  name: string
  fqdn: string
  domain: string
  group: string
  os: string
  ip: string
  agent: HostAgent
  agent_version: string
  last_seen_at: string | null
  product: string
  product_version: string
  protection: HostProtection
  rtp_state: number
  bases_at: string | null
  bases: HostBases
  last_fullscan_at: string | null
  status: 'ok' | 'warning' | 'critical'
  threats: number
  unassigned: boolean
  in_ad: 'both' | 'ksc_only' | null
  components: [string, number][]
  findings: number
}

export interface HostsQuery {
  group?: string
  product?: string
  agent?: HostAgent
  protection?: HostProtection
  bases?: HostBases
  in_ad?: string
  status?: string
  q?: string
  limit?: number
  offset?: number
}

export interface HostsResponse {
  total: number
  items: Host[]
  facets: {
    group: Record<string, number>
    product: Record<string, number>
    agent: Record<HostAgent, number>
    protection: Record<HostProtection, number>
    bases: Record<HostBases, number>
    in_ad: Record<string, number>
    status: Record<string, number>
  } | null
}

export interface HostDetail extends Omit<Host, 'findings'> {
  findings: { key: string; check: string; check_title: string; severity: Severity; status: FindingStatus; details: Record<string, unknown> }[]
}

export interface KscConfig {
  agent_silent_days: number
  bases_old_days: number
  fullscan_days: number
  license_days: number
  key_components: Record<string, string[]>
  allowlist_hosts: string[]
}

export interface SettingsView {
  config: KscConfig
  defaults: KscConfig
  checks: { code: string; title: string; description: string }[]
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
  import_file: 'Загрузка выгрузки',
  collect: 'Сбор из KSC',
  reanalyze: 'Пересчёт снапшота',
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
