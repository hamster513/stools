import { useEffect, useState } from 'react'
import { Plus, RotateCcw, Save, Trash2 } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useSaveAdSettings } from '@/modules/ad/api/queries'
import type { AdConfig, SettingsView } from '@/modules/ad/api/types'
import { Button } from '@/components/ui/Button'
import { useCan } from '@/lib/can'
import { Field, FIELD, Section } from '@/platform/collector/ui'

const AREA = FIELD + ' font-mono text-xs min-h-[72px]'

function lines(v: string[]): string { return v.join('\n') }
function parseLines(s: string): string[] { return s.split('\n').map((x) => x.trim()).filter(Boolean) }
function rids(v: number[]): string { return v.join(', ') }
function parseRids(s: string): number[] { return s.split(/[\s,]+/).filter(Boolean).map(Number).filter(Number.isInteger) }

type RidField = 'adcs_safe_rids' | 'admin_rids' | 'tier0_safe_rids'
type OsRow = [build: string, date: string]

function ridTexts(c: AdConfig): Record<RidField, string> {
  return { adcs_safe_rids: rids(c.adcs_safe_rids), admin_rids: rids(c.admin_rids), tier0_safe_rids: rids(c.tier0_safe_rids) }
}
function osRows(c: AdConfig): OsRow[] { return Object.entries(c.obsolete_os_builds) }
// Неполные строки (без сборки или даты) не сохраняются, но остаются в таблице до перезагрузки.
function parseOsRows(rows: OsRow[]): Record<string, string> { return Object.fromEntries(rows.map(([b, d]) => [b.trim(), d]).filter(([b, d]) => b && d)) }

type DayKey = 'admin_password_max_age_days' | 'builtin_admin_recent_days' | 'computer_inactivity_days' | 'computer_password_max_age_days' | 'azure_sso_key_max_age_days'
  | 'backup_max_age_days' | 'trust_inactive_days' | 'smartcard_password_max_age_days' | 'dc_max_uptime_days'
const DAYS: { key: DayKey; label: string; hint: string }[] = [
  { key: 'admin_password_max_age_days', label: 'Пароль админа старше, дней', hint: 'AdminPasswordAge' },
  { key: 'builtin_admin_recent_days', label: 'Вход Administrator за, дней', hint: 'BuiltinAdminUsed: встроенная учётка RID 500' },
  { key: 'computer_inactivity_days', label: 'Неактивность компьютера, дней', hint: 'InactiveComputers; ObsoleteOs учитывает только активные' },
  { key: 'computer_password_max_age_days', label: 'Пароль компьютера старше, дней', hint: 'ComputerPasswordAge; у контроллера порог 45' },
  { key: 'azure_sso_key_max_age_days', label: 'Ключ Entra SSO старше, дней', hint: 'AzureSsoKeyAge: ключ Seamless SSO' },
  { key: 'backup_max_age_days', label: 'Резервная копия AD старше, дней', hint: 'BackupAge: по dSASignature корня домена' },
  { key: 'dc_max_uptime_days', label: 'Контроллер не перезагружался, дней', hint: 'DcHardening (uptime): по времени загрузки из данных контроллеров' },
  { key: 'trust_inactive_days', label: 'Доверие не менялось, дней', hint: 'TrustSecurity: пароль доверия не обновляется' },
  { key: 'smartcard_password_max_age_days', label: 'Пароль учётки «только смарт-карта» старше, дней', hint: 'SmartcardPassword, если домен не меняет его сам' },
]
const LIMITS: { key: 'password_min_length' | 'control_path_many'; label: string; hint: string }[] = [
  { key: 'password_min_length', label: 'Минимальная длина пароля', hint: 'PasswordPolicy: политика домена и каждая PSO' },
  { key: 'control_path_many', label: 'Участников больше — как широкая группа', hint: 'CriticalObjectAcl: субъект с правами на критичный объект' },
]

/** Правила проверок — то, что в прототипе лежало в AD_audit.config.json. */
export function RulesSection({ settings }: { settings: SettingsView }) {
  // Правила аудитор читает: по ним считались находки, которые он разбирает.
  const { write } = useCan()
  const save = useSaveAdSettings()
  const [cfg, setCfg] = useState<AdConfig>(settings.config)
  const [dirty, setDirty] = useState(false)
  // RID вводятся через запятую: текст держим отдельно, иначе запятая в конце стиралась бы при вводе.
  const [ridsText, setRidsText] = useState(ridTexts(settings.config))
  // Сборки ОС — строками: пока номер или дата не введены, строка не должна пропадать из таблицы.
  const [builds, setBuilds] = useState<OsRow[]>(osRows(settings.config))
  const reset = (c: AdConfig) => { setCfg(c); setRidsText(ridTexts(c)); setBuilds(osRows(c)) }
  useEffect(() => { reset(settings.config); setDirty(false) }, [settings.config])
  const patch = (p: Partial<AdConfig>) => { setDirty(true); setCfg((c) => ({ ...c, ...p })) }
  const ridField = (key: RidField) => (
    <textarea className={AREA} value={ridsText[key]} onChange={(e) => { setRidsText((t) => ({ ...t, [key]: e.target.value })); patch({ [key]: parseRids(e.target.value) }) }} spellCheck={false} disabled={!write} />
  )
  const setRows = (rows: OsRow[]) => { setBuilds(rows); patch({ obsolete_os_builds: parseOsRows(rows) }) }

  return (
    <Section id="rules" title="Правила проверок" about="Allowlist понижает находку до Low и помечает её; привилегированные группы ищутся по RID (не зависят от языка домена) и по именам. После изменения пересчитайте нужные снапшоты на экране «Снапшоты».">
      <div className="grid gap-4 md:grid-cols-2">
        <Field label="Allowlist: короткие имена" hint="По одному в строке, без домена; регистр не важен"><textarea className={AREA} value={lines(cfg.allowlist_short)} onChange={(e) => patch({ allowlist_short: parseLines(e.target.value) })} disabled={!write} /></Field>
        <Field label="Allowlist: полные имена" hint="Например NT AUTHORITY\SYSTEM"><textarea className={AREA} value={lines(cfg.allowlist_full)} onChange={(e) => patch({ allowlist_full: parseLines(e.target.value) })} disabled={!write} /></Field>
        <Field label="Привилегированные группы (имена)" hint="Дополнительно к RID 512, 519, 518, 544, 548, 551, 549, 550, 552, 517, 520, 526, 527"><textarea className={AREA} value={lines(cfg.privileged_groups)} onChange={(e) => patch({ privileged_groups: parseLines(e.target.value) })} disabled={!write} /></Field>
        <Field label="Низкопривилегированные группы" hint="Для проверки шаблонов AD CS; SID Everyone, Authenticated Users, BUILTIN\Users и RID 513/515 учитываются всегда"><textarea className={AREA} value={lines(cfg.low_priv_groups)} onChange={(e) => patch({ low_priv_groups: parseLines(e.target.value) })} disabled={!write} /></Field>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Неактивность, дней"><input className={FIELD} type="number" min={1} value={cfg.user_inactivity_days} onChange={(e) => patch({ user_inactivity_days: Number(e.target.value) })} disabled={!write} /></Field>
          <Field label="Срок пароля krbtgt, дней"><input className={FIELD} type="number" min={1} value={cfg.krbtgt_max_age_days} onChange={(e) => patch({ krbtgt_max_age_days: Number(e.target.value) })} disabled={!write} /></Field>
          <Field label="Sensitive ACL: область"><select className={FIELD} value={cfg.sensitive_acl_scope} onChange={(e) => patch({ sensitive_acl_scope: e.target.value })} disabled={!write}><option value="Both">OU и компьютеры</option><option value="OUs">Только OU</option><option value="Computers">Только компьютеры</option></select></Field>
          <Field label="Sensitive ACL: не больше объектов" hint="0 — без ограничения"><input className={FIELD} type="number" min={0} value={cfg.sensitive_acl_max_objects} onChange={(e) => patch({ sensitive_acl_max_objects: Number(e.target.value) })} disabled={!write} /></Field>
          <Field label="Sensitive ACL: search base" hint="DN; пусто — весь домен"><input className={FIELD} value={cfg.sensitive_acl_search_base} onChange={(e) => patch({ sensitive_acl_search_base: e.target.value })} spellCheck={false} disabled={!write} /></Field>
          <Field label="Sensitive ACL: порог массовых прав" hint="Явное право у одного субъекта больше чем на стольких объектах — одна находка"><input className={FIELD} type="number" min={1} max={100000} value={cfg.sensitive_acl_collapse_threshold} onChange={(e) => patch({ sensitive_acl_collapse_threshold: Number(e.target.value) })} disabled={!write || !cfg.sensitive_acl_collapse} /></Field>
          <label className="flex items-center gap-2 text-xs text-text sm:col-span-2"><input type="checkbox" className="accent-primary" checked={cfg.sensitive_acl_collapse} onChange={(e) => patch({ sensitive_acl_collapse: e.target.checked })} disabled={!write} /> Sensitive ACL: сворачивать унаследованные и массовые права</label>
        </div>
        <div>
          <Field label="Sensitive ACL: исключить OU" hint="DN-суффиксы, по одному в строке"><textarea className={AREA} value={lines(cfg.sensitive_acl_exclude_ous)} onChange={(e) => patch({ sensitive_acl_exclude_ous: parseLines(e.target.value) })} disabled={!write} /></Field>
          <div className="mt-3 mb-1 text-xs font-medium text-text">User Rights Assignment</div>
          <table className="text-xs">
            <tbody>
              {cfg.user_rights.map((r, i) => (
                <tr key={r.right}>
                  <td className="py-0.5 pr-3 font-mono text-text-secondary">{r.right}</td>
                  <td className="py-0.5">
                    <select className={FIELD + ' w-32'} value={r.severity} onChange={(e) => patch({ user_rights: cfg.user_rights.map((x, j) => (j === i ? { ...x, severity: e.target.value } : x)) })} disabled={!write}>
                      {['Critical', 'High', 'Medium', 'Low'].map((s) => <option key={s} value={s}>{s}</option>)}
                    </select>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="md:col-span-2">
          <div className="text-xs font-medium text-text">AD CS: безопасные заявители</div>
          <p className="mb-2 text-xs text-text-secondary">Все остальные субъекты с правом Enroll считаются заявителями под вопросом.</p>
          <div className="grid gap-3 sm:grid-cols-3">
            <Field label="SID" hint="По одному в строке"><textarea className={AREA} value={lines(cfg.adcs_safe_sids)} onChange={(e) => patch({ adcs_safe_sids: parseLines(e.target.value) })} disabled={!write} /></Field>
            <Field label="RID доменов своего леса" hint="Числа через запятую">{ridField('adcs_safe_rids')}</Field>
            <Field label="Имена групп" hint="По одному в строке; свои группы администраторов ЦС"><textarea className={AREA} value={lines(cfg.adcs_safe_principals)} onChange={(e) => patch({ adcs_safe_principals: parseLines(e.target.value) })} disabled={!write} /></Field>
          </div>
        </div>
        <div className="md:col-span-2">
          <div className="text-xs font-medium text-text">Гигиена учётных записей и компьютеров</div>
          <p className="mb-2 text-xs text-text-secondary">Пороги проверок гигиены. Админ — включённый пользователь, рекурсивный член групп из списка RID, и встроенный Administrator (RID 500).</p>
          <div className="grid gap-3 sm:grid-cols-3">
            <Field label="Группы админов (RID)" hint="Числа через запятую; 544–582 — встроенные (S-1-5-32-RID), остальные — RID домена">{ridField('admin_rids')}</Field>
            <Field label="Безопасные субъекты прав (RID)" hint="RID доменов своего леса: права на корень домена, владелец контроллера и т. п.">{ridField('tier0_safe_rids')}</Field>
            <Field label="Админов не больше" hint="TooManyAdmins"><input className={FIELD} type="number" min={1} value={cfg.admins_max} onChange={(e) => patch({ admins_max: Number(e.target.value) })} disabled={!write} /></Field>
            {[...LIMITS, ...DAYS].map((d) => (
              <Field key={d.key} label={d.label} hint={d.hint}><input className={FIELD} type="number" min={1} value={cfg[d.key]} onChange={(e) => patch({ [d.key]: Number(e.target.value) })} disabled={!write} /></Field>
            ))}
          </div>
          <div className="mt-3 mb-1 text-xs font-medium text-text">Сборки Windows и окончание поддержки</div>
          <p className="mb-2 text-xs text-text-secondary">Номер сборки из operatingSystemVersion, например 22621 для «10.0 (22621)». После даты компьютер с этой сборкой попадает в ObsoleteOs.</p>
          <table className="text-xs">
            <tbody>
              {builds.map(([build, date], i) => (
                <tr key={i}>
                  <td className="py-0.5 pr-2"><input className={FIELD + ' w-28 font-mono'} value={build} placeholder="22621" aria-label="Сборка" onChange={(e) => setRows(builds.map((r, j) => (j === i ? [e.target.value, r[1]] : r)))} spellCheck={false} disabled={!write} /></td>
                  <td className="py-0.5 pr-2"><input className={FIELD + ' w-40'} type="date" value={date} aria-label="Окончание поддержки" onChange={(e) => setRows(builds.map((r, j) => (j === i ? [r[0], e.target.value] : r)))} disabled={!write} /></td>
                  {write && <td className="py-0.5"><Button onClick={() => setRows(builds.filter((_, j) => j !== i))} aria-label="Удалить сборку"><Trash2 size={13} aria-hidden /></Button></td>}
                </tr>
              ))}
            </tbody>
          </table>
          {write && <Button className="mt-2" onClick={() => setRows([...builds, ['', '']])}><Plus size={13} aria-hidden /> Добавить сборку</Button>}
        </div>
      </div>
      {write && (
        <div className="mt-4 flex items-center gap-2 border-t border-grid pt-3">
          <Button variant="primary" onClick={() => save.mutate(cfg, { onSuccess: () => setDirty(false) })} loading={save.isPending} disabled={!dirty}><Save size={13} aria-hidden /> Сохранить</Button>
          <Button onClick={() => { setDirty(true); reset(settings.defaults) }}><RotateCcw size={13} aria-hidden /> По умолчанию</Button>
          {save.error && <span className="text-xs text-kind-1">{save.error instanceof ApiRequestError ? save.error.message : 'Не удалось сохранить'}</span>}
        </div>
      )}
    </Section>
  )
}
