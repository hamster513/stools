/** Типы API модуля Kaspersky Security Center (docs/ksc/api.md, спека §7). */

import type { FindingStatus } from '@/platform/findings/types'
import type {
  FindingBase,
  FindingDetail as CollectorFindingDetail,
  FindingsResponse as CollectorFindingsResponse,
  OverviewBase,
  Severity,
  SnapshotBase,
} from '@/platform/collector/types'

export { SEVERITIES, SEVERITY_LABELS, STAGE_LABELS } from '@/platform/collector/types'
export type { CheckSummary, FindingsQuery, Job, JobStatus, Severity } from '@/platform/collector/types'
export type { FindingStatus } from '@/platform/findings/types'

export interface Server {
  id: number
  name: string
  version: string
  snapshots: number
  last_snapshot_id: number | null
  last_snapshot_at: string | null
}

export interface Snapshot extends SnapshotBase {
  server_id: number
  source: 'file' | 'online'
  hosts: number
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

export interface Overview extends OverviewBase {
  server: { id: number; name: string; version: string }
  snapshot: (NonNullable<OverviewBase['snapshot']> & { hosts: number }) | null
  coverage: Coverage | null
}

export interface Finding extends FindingBase {
  host: string
}

export type FindingsResponse = CollectorFindingsResponse<Finding>
export type FindingDetail = CollectorFindingDetail<Finding>

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

/** Расширенные поля хоста (блок «Система» карточки), из `HostRecord.extra`. */
export interface HostExtra {
  os_build: number
  cpu_arch: number
  vm_type: number
  reboot_required: boolean
  reboot_requested_at: string | null
  reboot_reason: number
  edr_status: number
  managed_by_other_server: boolean
}

/** KLHST_WKS_CPU_ARCH. */
export const CPU_ARCH_LABELS: Record<number, string> = {
  1: 'x86',
  2: 'x64',
  4: 'arm64',
}

/** HST_VM_TYPE. */
export const VM_TYPE_LABELS: Record<number, string> = {
  2: 'физическая машина',
  3: 'VMware',
  4: 'Hyper-V',
  8: 'Xen',
  9: 'KVM',
  1: 'виртуальная машина',
}

export function vmTypeLabel(code: number): string {
  return VM_TYPE_LABELS[code] ?? 'неизвестно'
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
  extra: HostExtra
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
  findings: { key: string; check: string; check_title: string; severity: Severity; status: FindingStatus; status_title: string; details: Record<string, unknown> }[]
  /** Учитываемые находки хоста — то же правило, что счётчик в списке хостов. */
  findings_counted: number
}

export interface LockCount {
  total: number
  locked: number
  /** Настройки с признаком замка; 0 — замки в политике не распознаны. */
  with_lock_flag: number
}

export interface PolicyItem {
  id: number
  name: string
  product: string
  active: boolean
  inherited: boolean
  accept_parent: boolean
  modified_at: string | null
  modified_group: string
  locks: LockCount | null
  has_contents: boolean
}

export interface TaskItem {
  id: string
  name: string
  type: string
  product: string
  inherited: boolean
  schedule: number
  last_run_at: string | null
  ok: number
  warning: number
  failed: number
}

export interface PolicyFinding {
  key: string
  check: string
  check_title: string
  severity: Severity
}

export interface PolicyGroup {
  id: number
  name: string
  path: string
  level: number
  hosts: number
  policies: PolicyItem[]
  tasks: TaskItem[]
  findings: PolicyFinding[]
}

export interface PoliciesResponse {
  groups: PolicyGroup[]
}

export interface PolicyHeader {
  id: number
  name: string
  product: string
  version: string
  group: string
}

export interface LockSummary {
  total: number
  locked: number
  /** Доля замкнутых среди настроек с признаком замка. */
  share: number
  /** Настройки с признаком замка; 0 — замки в политике не распознаны. */
  with_lock_flag: number
}

export interface PolicySetting {
  path: string
  value: string
  locked: boolean | null
  inherited_lock: boolean
  lock_from: string
}

export interface PolicySection {
  name: string
  settings: PolicySetting[]
}

export interface PolicyContents {
  policy: PolicyHeader
  summary: LockSummary | null
  sections: PolicySection[]
  errors: string[]
}

export interface ServerAdmin {
  account: string
  internal: boolean
  role: string
  group: string
}

export interface ServerCert {
  function: string
  subject: string
  not_after: string
  days_left: number
}

export interface ServerSecondaryServer {
  name: string
  address: string
  version: string
  last_connected: string | null
  status: number
}

export interface ServerUpdateAgent {
  host: string
  group: string
}

export interface ServerFinding {
  key: string
  check: string
  check_title: string
  severity: Severity
  target: string
}

export interface ServerData {
  two_factor_required_for_all: boolean | null
  admins: ServerAdmin[]
  certs: ServerCert[]
  secondary_servers: ServerSecondaryServer[]
  update_agents: ServerUpdateAgent[]
  warnings: string[]
  findings: ServerFinding[]
}

export interface Connection {
  id: number
  title: string
  host: string
  port: number
  username: string
  password_set: boolean
  verify_tls: boolean
  internal: boolean
  domain: string
  server_id: number | null
  skip_policy_contents: boolean
}

export interface ConnectionIn {
  title: string
  host: string
  port: number
  username: string
  password: string
  verify_tls: boolean
  internal: boolean
  domain: string
  skip_policy_contents: boolean
}

export interface KscConfig {
  agent_silent_days: number
  bases_old_days: number
  fullscan_days: number
  license_days: number
  key_components: Record<string, string[]>
  allowlist_hosts: string[]
  task_failed_share: number
  task_stale_days: number
  reboot_pending_days: number
  cert_days: number
  admin_role_patterns: string[]
  policy_lock_share: number
  policy_contents_max_policies: number
}

export interface SettingsView {
  config: KscConfig
  defaults: KscConfig
  checks: { code: string; title: string; description: string }[]
}

export const JOB_KIND_LABELS: Record<string, string> = {
  import_file: 'Загрузка выгрузки',
  collect: 'Сбор из KSC',
  reanalyze: 'Пересчёт снапшота',
}
