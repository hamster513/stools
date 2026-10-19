/** Типы API модуля Active Directory (docs/ad/api.md, спека §7). */

import type {
  FindingBase,
  FindingDetail as CollectorFindingDetail,
  FindingsResponse as CollectorFindingsResponse,
  OverviewBase,
  ScheduleView,
  SnapshotBase,
} from '@/platform/collector/types'

export { SEVERITIES, SEVERITY_LABELS, STAGE_LABELS } from '@/platform/collector/types'
export type { CheckSummary, FindingsQuery, Job, JobStatus, ScheduleIn, ScheduleView, Severity } from '@/platform/collector/types'
export type { FindingStatus } from '@/platform/findings/types'

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

export interface Snapshot extends SnapshotBase {
  domain_id: number
  source: 'ldap' | 'file'
  objects: number
}

export interface Overview extends OverviewBase {
  domain: { id: number; dns_root: string; netbios: string; dn?: string; sid?: string }
  snapshot: (NonNullable<OverviewBase['snapshot']> & { objects: number }) | null
}

export interface Finding extends FindingBase {
  identity: string
  identity_sid: string
  right: string
}

export type FindingsResponse = CollectorFindingsResponse<Finding>
export type FindingDetail = CollectorFindingDetail<Finding>

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
  admins_max: number
  admin_password_max_age_days: number
  builtin_admin_recent_days: number
  azure_sso_key_max_age_days: number
  computer_inactivity_days: number
  computer_password_max_age_days: number
  password_min_length: number
  backup_max_age_days: number
  smartcard_password_max_age_days: number
  trust_inactive_days: number
  control_path_many: number
  /** Сборка Windows → дата окончания поддержки (ГГГГ-ММ-ДД). */
  obsolete_os_builds: Record<string, string>
  low_priv_groups: string[]
  low_priv_sids: string[]
  low_priv_rids: number[]
  adcs_safe_sids: string[]
  adcs_safe_rids: number[]
  adcs_safe_principals: string[]
  admin_rids: number[]
  tier0_safe_rids: number[]
  sensitive_acl_scope: string
  sensitive_acl_search_base: string
  sensitive_acl_exclude_ous: string[]
  sensitive_acl_max_objects: number
  sensitive_acl_collapse: boolean
  sensitive_acl_collapse_threshold: number
}

export interface SettingsView {
  config: AdConfig
  defaults: AdConfig
  checks: { code: string; title: string; description: string }[]
}

/** Загрузка данных центра сертификации (stools-ad-ca/1); cas/dcs/web — число записей. */
export interface CaData {
  id: number
  collected_at: string
  imported_at: string
  filename: string
  uploaded_by: string
  sections: string[]
  cas: number
  dcs: number
  web: number
}

export const CA_SECTION_LABELS: Record<string, string> = {
  ca: 'настройки и права ЦС',
  dc: 'реестр контроллеров',
  web: 'веб-выдача',
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
  page_size: number
  pause_ms: number
  domain_id: number | null
  /** Расписание сбора; null — не задано. */
  schedule: ScheduleView | null
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
  page_size: number
  pause_ms: number
}

export const JOB_KIND_LABELS: Record<string, string> = {
  import_file: 'Загрузка выгрузки',
  collect: 'Сбор по LDAP',
  reanalyze: 'Пересчёт снапшота',
}
