import { useEffect, useState } from 'react'
import { RotateCcw, Save } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useSaveAdSettings } from '@/modules/ad/api/queries'
import type { AdConfig, SettingsView } from '@/modules/ad/api/types'
import { Button } from '@/components/ui/Button'
import { useCan } from '@/lib/can'
import { Field, FIELD, Section } from '@/platform/collector/ui'

const AREA = FIELD + ' font-mono text-xs min-h-[72px]'

function lines(v: string[]): string { return v.join('\n') }
function parseLines(s: string): string[] { return s.split('\n').map((x) => x.trim()).filter(Boolean) }

/** Правила проверок — то, что в прототипе лежало в AD_audit.config.json. */
export function RulesSection({ settings }: { settings: SettingsView }) {
  // Правила аудитор читает: по ним считались находки, которые он разбирает.
  const { write } = useCan()
  const save = useSaveAdSettings()
  const [cfg, setCfg] = useState<AdConfig>(settings.config)
  const [dirty, setDirty] = useState(false)
  useEffect(() => { setCfg(settings.config); setDirty(false) }, [settings.config])
  const patch = (p: Partial<AdConfig>) => { setDirty(true); setCfg((c) => ({ ...c, ...p })) }

  return (
    <Section title="Правила проверок" about="Allowlist понижает находку до Low и помечает её; привилегированные группы ищутся по RID (не зависят от языка домена) и по именам. После изменения пересчитайте нужные снапшоты на экране «Снапшоты».">
      <div className="grid gap-4 md:grid-cols-2">
        <Field label="Allowlist: короткие имена" hint="По одному в строке, без домена; регистр не важен"><textarea className={AREA} value={lines(cfg.allowlist_short)} onChange={(e) => patch({ allowlist_short: parseLines(e.target.value) })} disabled={!write} /></Field>
        <Field label="Allowlist: полные имена" hint="Например NT AUTHORITY\SYSTEM"><textarea className={AREA} value={lines(cfg.allowlist_full)} onChange={(e) => patch({ allowlist_full: parseLines(e.target.value) })} disabled={!write} /></Field>
        <Field label="Привилегированные группы (имена)" hint="Дополнительно к RID 512, 519, 518, 544, 548, 551, 549"><textarea className={AREA} value={lines(cfg.privileged_groups)} onChange={(e) => patch({ privileged_groups: parseLines(e.target.value) })} disabled={!write} /></Field>
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
      </div>
      {write && (
        <div className="mt-4 flex items-center gap-2 border-t border-grid pt-3">
          <Button variant="primary" onClick={() => save.mutate(cfg, { onSuccess: () => setDirty(false) })} loading={save.isPending} disabled={!dirty}><Save size={13} aria-hidden /> Сохранить</Button>
          <Button onClick={() => { setDirty(true); setCfg(settings.defaults) }}><RotateCcw size={13} aria-hidden /> По умолчанию</Button>
          {save.error && <span className="text-xs text-kind-1">{save.error instanceof ApiRequestError ? save.error.message : 'Не удалось сохранить'}</span>}
        </div>
      )}
    </Section>
  )
}
