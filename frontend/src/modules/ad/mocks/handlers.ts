/**
 * Обработчики MSW модуля AD — ровно столько, чтобы в `npm run dev` открывались
 * обзор домена, сводка и настройки: проверки двух категорий, три из них AD CS (две
 * проверены частично), и загрузки данных ЦС. Находки и снапшоты не отвечаются.
 * Второй домен — со снапшотом, посчитанным до сводки: его сводка отвечает 409.
 */
import { http, HttpResponse } from 'msw'
import { noSession } from '@/modules/siem/mocks/handlers'
import type { AdConfig, CaData, CheckSummary, DcLink, Domain, Overview, SettingsView, Summary, SummaryBucket } from '@/modules/ad/api/types'

const DOMAIN: Domain = { id: 1, sid: 'S-1-5-21-1000-2000-3000', dns_root: 'corp.local', netbios: 'CORP', dn: 'DC=corp,DC=local', snapshots: 1, last_snapshot_id: 1, last_snapshot_at: '2026-09-30T09:00:00Z' }
const STALE_DOMAIN: Domain = { id: 2, sid: 'S-1-5-21-1000-2000-4000', dns_root: 'lab.corp.local', netbios: 'LAB', dn: 'DC=lab,DC=corp,DC=local', snapshots: 1, last_snapshot_id: 2, last_snapshot_at: '2026-09-12T09:00:00Z' }
/** Снапшот, посчитанный до сводки (анализатор до версии 9). */
const STALE_SNAPSHOT_ID = 2

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

const WEIGHTS = { Critical: 40, High: 20, Medium: 10, Low: 3, Info: 0 }

/** Та же формула, что backend/api/modules/ad/core/score.py: вес худшей находки проверки, сумма по категории до 100. */
function score(): NonNullable<Overview['score']> {
  const categories: NonNullable<Overview['score']>['categories'] = {}
  for (const c of CHECKS) {
    const cat = (categories[c.category ?? ''] ??= { title: c.category_title ?? '', score: 0, checks: [] })
    const severity = (Object.keys(WEIGHTS) as (keyof typeof WEIGHTS)[]).find((s) => c.by_severity[s] > 0)
    if (severity && WEIGHTS[severity] > 0) cat.checks.push({ code: c.code, severity, points: WEIGHTS[severity] })
  }
  for (const cat of Object.values(categories)) cat.score = Math.min(100, cat.checks.reduce((a, c) => a + c.points, 0))
  return { total: Math.max(...Object.values(categories).map((c) => c.score)), categories }
}

function overview(domain: Domain): Overview {
  const by_severity = { ...NONE }
  for (const c of CHECKS) for (const [s, n] of Object.entries(c.by_severity)) by_severity[s as keyof typeof NONE] += n
  return {
    domain: { id: domain.id, dns_root: domain.dns_root, netbios: domain.netbios },
    snapshot: { id: domain.last_snapshot_id ?? 1, collected_at: domain.last_snapshot_at ?? '2026-09-30T09:00:00Z', source: 'file', collector: 'powershell 2.0', findings: CHECKS.reduce((a, c) => a + c.total, 0), by_severity, objects: 1840 },
    compared_to: { previous_id: null, collected_at: null, new: 0, fixed: 0 },
    counted: { total: CHECKS.reduce((a, c) => a + c.total, 0), by_severity, statuses: ['new', 'in_work', 'fixed', 'reopened'] },
    summary: {
      by_status: { new: CHECKS.reduce((a, c) => a + c.total, 0), in_work: 0, risk_accepted: 0, false_positive: 0, fixed: 0, resolved: 0, reopened: 0 },
      overdue: 0, risk_expiring: 0, unassigned: CHECKS.reduce((a, c) => a + c.total, 0),
    },
    checks: CHECKS,
    score: score(),
    score_history: [
      { snapshot_id: 101, collected_at: '2026-08-31T09:00:00Z', total: 80 },
      { snapshot_id: 102, collected_at: '2026-09-10T09:00:00Z', total: 60 },
      { snapshot_id: 103, collected_at: '2026-09-20T09:00:00Z', total: 50 },
      { snapshot_id: domain.last_snapshot_id ?? 1, collected_at: domain.last_snapshot_at ?? '2026-09-30T09:00:00Z', total: score().total },
    ],
  }
}

const buckets = (...n: number[]): SummaryBucket[] => [30, 90, 180, 365, 730, 1095, null].map((le, i) => ({ le, n: n[i] ?? 0 }))
const counts = (total: number, enabled: number, active: number, flags: Partial<Summary['accounts']['users']> = {}) => ({
  total, enabled, disabled: total - enabled, active, inactive: enabled - active,
  pwd_never_expires: 0, pwd_not_required: 0, no_preauth: 0, sid_history: 0, delegation: 0, laps: 0, ...flags,
})
const OU = 'OU=Servers,DC=corp,DC=local'

// 64 GPO — больше первой страницы в 50, чтобы видна была кнопка «показать все».
const SUMMARY: Summary = {
  version: 1,
  accounts: {
    users: counts(1240, 1105, 860, { pwd_never_expires: 37, pwd_not_required: 4, no_preauth: 2, sid_history: 3, delegation: 1 }),
    computers: counts(600, 571, 498, { delegation: 2, laps: 512 }),
  },
  password_age: { all: buckets(180, 260, 210, 190, 140, 60, 65), admins: buckets(3, 4, 2, 1, 1, 0, 1) },
  last_logon: { all: buckets(820, 40, 30, 60, 55, 40, 60), admins: buckets(9, 1, 0, 1, 0, 0, 1) },
  os: [
    { name: 'Windows 10 Enterprise', build: '19045', total: 380, enabled: 366, active: 330 },
    { name: 'Windows 11 Enterprise', build: '22631', total: 140, enabled: 139, active: 131 },
    { name: 'Windows Server 2022 Standard', build: '20348', total: 52, enabled: 50, active: 28 },
    { name: 'Windows Server 2012 R2 Standard', build: '9600', total: 16, enabled: 12, active: 6 },
    { name: '', build: '', total: 12, enabled: 4, active: 3 },
  ],
  dcs: [
    { name: 'DC01', dn: 'CN=DC01,OU=Domain Controllers,DC=corp,DC=local', dns: 'dc01.corp.local', os: 'Windows Server 2022 Standard', build: '20348', rodc: false, last_logon_days: 0, pwd_age_days: 12, owner: 'CORP\\Domain Admins' },
    { name: 'DC02', dn: 'CN=DC02,OU=Domain Controllers,DC=corp,DC=local', dns: 'dc02.corp.local', os: 'Windows Server 2019 Standard', build: '17763', rodc: false, last_logon_days: 1, pwd_age_days: 27, owner: 'CORP\\Domain Admins' },
    { name: 'RODC01', dn: 'CN=RODC01,OU=Domain Controllers,DC=corp,DC=local', dns: 'rodc01.branch.corp.local', os: 'Windows Server 2016 Standard', build: '14393', rodc: true, last_logon_days: 3, pwd_age_days: 41, owner: '' },
  ],
  groups: [
    { name: 'Domain Admins', sid: 'S-1-5-21-1000-2000-3000-512', members: 9, enabled: 8, inactive: 2, pwd_never_expires: 3, delegable: 7, protected_users: 1 },
    { name: 'Enterprise Admins', sid: 'S-1-5-21-1000-2000-3000-519', members: 2, enabled: 2, inactive: 0, pwd_never_expires: 1, delegable: 2, protected_users: 0 },
    { name: 'Schema Admins', sid: 'S-1-5-21-1000-2000-3000-518', members: 1, enabled: 1, inactive: 1, pwd_never_expires: 1, delegable: 1, protected_users: 0 },
    { name: 'Administrators', sid: 'S-1-5-32-544', members: 14, enabled: 11, inactive: 2, pwd_never_expires: 4, delegable: 10, protected_users: 1 },
  ],
  trusts: [
    { partner: 'partner.example', flat_name: 'PARTNER', direction: 3, type: 2, within_forest: false, changed: '2025-11-04T10:00:00Z' },
    { partner: 'branch.corp.local', flat_name: 'BRANCH', direction: 3, type: 2, within_forest: true, changed: '2026-08-20T07:30:00Z' },
    { partner: 'LEGACY.REALM', flat_name: '', direction: 1, type: 3, within_forest: false, changed: null },
  ],
  password_policies: [
    { name: 'Политика домена', min_length: 8, lockout_threshold: 0, complexity: true, reversible: false, precedence: null },
    { name: 'PSO-Admins', min_length: 15, lockout_threshold: 5, complexity: true, reversible: false, precedence: 10 },
    { name: 'PSO-ServiceAccounts', min_length: 20, lockout_threshold: 0, complexity: false, reversible: true, precedence: 20 },
  ],
  gpos: [
    { name: 'Default Domain Policy', dn: 'CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=corp,DC=local', machine_disabled: false, user_disabled: false, links: [{ dn: 'DC=corp,DC=local', enforced: false, disabled: false }] },
    { name: 'Default Domain Controllers Policy', dn: 'CN={6AC1786C-016F-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=corp,DC=local', machine_disabled: false, user_disabled: true, links: [{ dn: 'OU=Domain Controllers,DC=corp,DC=local', enforced: true, disabled: false }] },
    ...Array.from({ length: 62 }, (_, i) => ({
      name: `Servers baseline ${String(i + 1).padStart(2, '0')}`,
      dn: `CN={00000000-0000-0000-0000-${String(i + 1).padStart(12, '0')}},CN=Policies,CN=System,DC=corp,DC=local`,
      machine_disabled: false,
      user_disabled: i % 3 === 0,
      links: i % 10 === 9 ? [] : [{ dn: OU, enforced: false, disabled: i % 7 === 0 }],
    })),
  ],
  subnets: [
    { name: '10.10.0.0/16', site: 'Default-First-Site-Name' },
    { name: '10.20.0.0/24', site: 'Branch' },
  ],
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

// DC02 вне подсетей AD и без антивируса, RODC01 не найден ни в одном модуле.
const DC_LINKS: DcLink[] = [
  { name: 'DC01', asset_id: 1, ips: ['10.0.0.10'], in_ad_subnet: true, vm: { critical: 2, exploitable: 1 }, ksc_agent: true },
  { name: 'DC02', asset_id: 2, ips: ['10.9.0.11'], in_ad_subnet: false, vm: { critical: 0, exploitable: 0 }, ksc_agent: false },
  { name: 'RODC01', asset_id: null, ips: [], in_ad_subnet: null, vm: null, ksc_agent: null },
]

export const adHandlers = [
  http.get('/api/ad/domains', () => noSession() ?? HttpResponse.json([DOMAIN, STALE_DOMAIN])),
  http.get('/api/ad/domains/:id/overview', ({ params }) => noSession() ?? HttpResponse.json(overview(Number(params.id) === STALE_DOMAIN.id ? STALE_DOMAIN : DOMAIN))),
  http.get('/api/ad/snapshots/:id/summary', ({ params }) =>
    noSession() ??
    (Number(params.id) === STALE_SNAPSHOT_ID
      ? HttpResponse.json({ detail: 'сводка не посчитана: пересчитайте снапшот' }, { status: 409 })
      : HttpResponse.json(SUMMARY)),
  ),
  http.get('/api/ad/domains/:id/dc-links', () => noSession() ?? HttpResponse.json(DC_LINKS)),
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
