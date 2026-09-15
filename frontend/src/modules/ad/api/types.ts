/** Типы API модуля Active Directory (docs/ad/api.md, спека §7). */

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

export interface Domain {
  id: number
  sid: string
  dns_root: string
  netbios: string
  dn: string
  snapshots: number
  last_snapshot_id: number | null
  last_snapshot_at: string | null
}

export interface Snapshot {
  id: number
  domain_id: number
  collected_at: string
  imported_at: string
  source: 'ldap' | 'file'
  collector: string
  filename: string
  objects: number
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

export interface Overview {
  domain: { id: number; dns_root: string; netbios: string; dn?: string; sid?: string }
  snapshot: {
    id: number
    collected_at: string
    source: string
    collector: string
    objects: number
    findings: number
    by_severity: Record<Severity, number>
  } | null
  compared_to?: { previous_id: number | null; collected_at: string | null; new: number; fixed: number }
  accepted_total?: number
  checks: CheckSummary[]
}

export interface Finding {
  id: number
  key: string
  check: string
  check_title: string
  severity: Severity
  severity_original: Severity
  identity: string
  identity_sid: string
  target: string
  right: string
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

export interface UserRight {
  right: string
  severity: string
}

export interface AdConfig {
  allowlist_short: string[]
  allowlist_full: string[]
  privileged_groups: string[]
  privileged_rids: number[]
  user_rights: UserRight[]
  user_inactivity_days: number
  krbtgt_max_age_days: number
  low_priv_groups: string[]
  low_priv_sids: string[]
  low_priv_rids: number[]
  sensitive_acl_scope: string
  sensitive_acl_search_base: string
  sensitive_acl_exclude_ous: string[]
  sensitive_acl_max_objects: number
}

export interface SettingsView {
  config: AdConfig
  defaults: AdConfig
  checks: { code: string; title: string; description: string }[]
}

export interface Connection {
  id: number
  title: string
  host: string
  port: number
  use_ssl: boolean
  verify_tls: boolean
  username: string
  password_set: boolean
  base_dn: string
  collect_sysvol: boolean
  domain_id: number | null
}

export interface ConnectionIn {
  title: string
  host: string
  port: number
  use_ssl: boolean
  verify_tls: boolean
  username: string
  password: string
  base_dn: string
  collect_sysvol: boolean
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
  collect: 'Сбор по LDAP',
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
