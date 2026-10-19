/**
 * Обработчики MSW модуля AD — ровно столько, чтобы в `npm run dev` открывались
 * обзор домена и настройки: проверки двух категорий, три из них AD CS (две
 * проверены частично), и загрузки данных ЦС. Находки и снапшоты не отвечаются.
 */
import { http, HttpResponse } from 'msw'
import { noSession } from '@/modules/siem/mocks/handlers'
import type { AdConfig, CaData, CheckSummary, Domain, Overview, SettingsView } from '@/modules/ad/api/types'

const DOMAIN: Domain = { id: 1, sid: 'S-1-5-21-1000-2000-3000', dns_root: 'corp.local', netbios: 'CORP', dn: 'DC=corp,DC=local', snapshots: 1, last_snapshot_id: 1, last_snapshot_at: '2026-09-30T09:00:00Z' }

const NONE = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 }

const CATEGORY_TITLES: Record<string, string> = { kerberos: 'Kerberos и делегирование', pki: 'AD CS и сертификаты' }

function check(code: string, title: string, description: string, category: string, by: Partial<CheckSummary['by_severity']>, unchecked: string | null = null): CheckSummary {
  const by_severity = { ...NONE, ...by }
  const total = Object.values(by_severity).reduce((a, b) => a + b, 0)
  return { code, title, description, total, all: total, open: total, by_severity, new: 0, resolved: 0, unchecked, category, category_title: CATEGORY_TITLES[category] }
}

const CHECKS: CheckSummary[] = [
  check('ASREP', 'AS-REP roastable', 'Учётные записи без предварительной аутентификации Kerberos.', 'kerberos', { Medium: 2 }),
  check('RBCD', 'RBCD (AllowedToActOnBehalfOfOtherIdentity)', 'Делегирование на основе ресурсов.', 'kerberos', {}),
  check('ADCS_ESC', 'Шаблоны AD CS (ESC1–4, 9, 13, 15)', 'Шаблоны сертификатов, по которым небезопасный заявитель может выпустить сертификат для входа от чужого имени.', 'pki', { High: 2, Low: 1 }),
  check('ADCS_CA', 'Центр сертификации (ESC5–8, 11, 16)', 'Права на объекты PKI и центр сертификации, настройки ЦС и веб-выдачи. ESC12 (доступ к HSM) удалённо не определяется.', 'pki', { High: 1 }, 'ESC8 не проверен: нужна проверка веб-выдачи (сборщик, пункт 7)'),
  check('ADCS_MAPPING', 'Привязка сертификатов к учётным записям (ESC10, 14)', 'Слабая привязка сертификата к учётной записи на контроллерах и слабые явные сопоставления.', 'pki', {}, 'ESC10 не проверен: нужен реестр контроллеров (сборщик, пункт 6)'),
]

function overview(): Overview {
  const by_severity = { ...NONE }
  for (const c of CHECKS) for (const [s, n] of Object.entries(c.by_severity)) by_severity[s as keyof typeof NONE] += n
  return {
    domain: { id: DOMAIN.id, dns_root: DOMAIN.dns_root, netbios: DOMAIN.netbios },
    snapshot: { id: 1, collected_at: '2026-09-30T09:00:00Z', source: 'file', collector: 'powershell 2.0', findings: CHECKS.reduce((a, c) => a + c.total, 0), by_severity, objects: 1840 },
    compared_to: { previous_id: null, collected_at: null, new: 0, fixed: 0 },
    counted: { total: CHECKS.reduce((a, c) => a + c.total, 0), by_severity, statuses: ['new', 'in_work', 'fixed', 'reopened'] },
    summary: {
      by_status: { new: CHECKS.reduce((a, c) => a + c.total, 0), in_work: 0, risk_accepted: 0, false_positive: 0, fixed: 0, resolved: 0, reopened: 0 },
      overdue: 0, risk_expiring: 0, unassigned: CHECKS.reduce((a, c) => a + c.total, 0),
    },
    checks: CHECKS,
  }
}

const DEFAULTS: AdConfig = {
  allowlist_short: ['SYSTEM'],
  allowlist_full: ['NT AUTHORITY\\SYSTEM', 'BUILTIN\\ADMINISTRATORS'],
  privileged_groups: ['Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'DnsAdmins'],
  privileged_rids: [512, 519, 518, 544, 548, 551, 549, 550, 552, 517, 520, 526, 527],
  user_rights: [{ right: 'SeEnableDelegationPrivilege', severity: 'High' }, { right: 'SeBackupPrivilege', severity: 'Medium' }],
  user_inactivity_days: 90,
  krbtgt_max_age_days: 180,
  admins_max: 20,
  admin_password_max_age_days: 1095,
  builtin_admin_recent_days: 35,
  azure_sso_key_max_age_days: 90,
  computer_inactivity_days: 90,
  computer_password_max_age_days: 90,
  password_min_length: 8,
  backup_max_age_days: 7,
  dc_max_uptime_days: 180,
  smartcard_password_max_age_days: 90,
  trust_inactive_days: 40,
  control_path_many: 100,
  obsolete_os_builds: { '22000': '2024-10-08', '22621': '2025-10-14' },
  low_priv_groups: ['AUTHENTICATED USERS', 'DOMAIN USERS', 'USERS', 'EVERYONE'],
  low_priv_sids: ['S-1-1-0', 'S-1-5-11', 'S-1-5-32-545'],
  low_priv_rids: [513, 515],
  adcs_safe_sids: ['S-1-5-18', 'S-1-5-32-544', 'S-1-5-9'],
  adcs_safe_rids: [500, 512, 516, 518, 519, 498, 521, 517],
  adcs_safe_principals: [],
  admin_rids: [512, 518, 519, 544],
  tier0_safe_rids: [500, 512, 516, 518, 519, 498, 521],
  sensitive_acl_scope: 'Both',
  sensitive_acl_search_base: '',
  sensitive_acl_exclude_ous: [],
  sensitive_acl_max_objects: 0,
  sensitive_acl_collapse: true,
  sensitive_acl_collapse_threshold: 50,
}

let config: AdConfig = { ...DEFAULTS }

// Один раздел `ca` — поэтому ESC8 и ESC10 на обзоре не проверены.
let caData: CaData[] = [
  { id: 1, collected_at: '2026-09-30T08:40:00Z', imported_at: '2026-09-30T09:05:00Z', filename: 'adca-CORP-20260930.json.gz', uploaded_by: 'analyst', sections: ['ca'], cas: 1, dcs: 0, web: 0, dc_total: 0, dc_complete: 0 },
]

export const adHandlers = [
  http.get('/api/ad/domains', () => noSession() ?? HttpResponse.json([DOMAIN])),
  http.get('/api/ad/domains/:id/overview', () => noSession() ?? HttpResponse.json(overview())),
  http.get('/api/ad/domains/:id/ca-data', () => noSession() ?? HttpResponse.json(caData)),
  http.delete('/api/ad/ca-data/:id', ({ params }) => {
    const denied = noSession()
    if (denied) return denied
    caData = caData.filter((c) => c.id !== Number(params.id))
    return HttpResponse.json({ job_id: 1 }, { status: 202 })
  }),
  http.get('/api/ad/settings', () =>
    noSession() ?? HttpResponse.json<SettingsView>({ config, defaults: DEFAULTS, checks: CHECKS.map(({ code, title, description }) => ({ code, title, description })) }),
  ),
  http.put('/api/ad/settings', async ({ request }) => {
    const denied = noSession()
    if (denied) return denied
    config = (await request.json()) as AdConfig
    return HttpResponse.json({ config })
  }),
  http.get('/api/ad/connections', () => noSession() ?? HttpResponse.json([])),
  http.get('/api/ad/jobs', () => noSession() ?? HttpResponse.json([])),
]
