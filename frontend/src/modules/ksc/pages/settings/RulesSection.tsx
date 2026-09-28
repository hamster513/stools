import { useEffect, useState } from 'react'
import { RotateCcw, Save } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useSaveKscSettings } from '@/modules/ksc/api/queries'
import type { KscConfig, SettingsView } from '@/modules/ksc/api/types'
import { Button } from '@/components/ui/Button'
import { useCan } from '@/lib/can'
import { Field, FIELD, Section } from '@/platform/collector/ui'

const AREA = FIELD + ' font-mono text-xs min-h-[72px]'

function lines(v: string[]): string { return v.join('\n') }
function parseLines(s: string): string[] { return s.split('\n').map((x) => x.trim()).filter(Boolean) }
function csv(v: string[]): string { return v.join(', ') }
function parseCsv(s: string): string[] { return s.split(',').map((x) => x.trim()).filter(Boolean) }

/** Код компонента (KscConfig.key_components) → подпись по-русски. */
const COMPONENT_LABELS: Record<string, string> = {
  file_threat: 'Файловая защита',
  behavior_detection: 'Анализ поведения',
  exploit_prevention: 'Защита от эксплойтов',
  firewall: 'Сетевой экран',
  network_threat: 'Защита от сетевых угроз',
  web_control: 'Веб-контроль',
  device_control: 'Контроль устройств',
}

function ReadOnlyView({ config }: { config: KscConfig }) {
  return (
    <dl className="grid gap-x-6 gap-y-2 text-xs sm:grid-cols-2">
      <div className="flex justify-between gap-2 sm:block"><dt className="text-text-secondary">Агент молчит, дней</dt><dd className="font-mono text-text">{config.agent_silent_days}</dd></div>
      <div className="flex justify-between gap-2 sm:block"><dt className="text-text-secondary">Базы устарели, дней</dt><dd className="font-mono text-text">{config.bases_old_days}</dd></div>
      <div className="flex justify-between gap-2 sm:block"><dt className="text-text-secondary">Нет полного поиска, дней</dt><dd className="font-mono text-text">{config.fullscan_days}</dd></div>
      <div className="flex justify-between gap-2 sm:block"><dt className="text-text-secondary">Лицензия истекает, дней</dt><dd className="font-mono text-text">{config.license_days}</dd></div>
      <div className="flex justify-between gap-2 sm:block"><dt className="text-text-secondary">Провалы задачи → High, доля</dt><dd className="font-mono text-text">{config.task_failed_share}</dd></div>
      <div className="flex justify-between gap-2 sm:block"><dt className="text-text-secondary">Задача обновления не запускалась, дней</dt><dd className="font-mono text-text">{config.task_stale_days}</dd></div>
      <div className="flex justify-between gap-2 sm:block"><dt className="text-text-secondary">Зависла перезагрузка, дней</dt><dd className="font-mono text-text">{config.reboot_pending_days}</dd></div>
      <div className="flex justify-between gap-2 sm:block"><dt className="text-text-secondary">Сертификат истекает, дней</dt><dd className="font-mono text-text">{config.cert_days}</dd></div>
      <div className="flex justify-between gap-2 sm:block"><dt className="text-text-secondary">Мало замков в политике, доля</dt><dd className="font-mono text-text">{config.policy_lock_share}</dd></div>
      <div className="flex justify-between gap-2 sm:block"><dt className="text-text-secondary">Содержимое политик, максимум</dt><dd className="font-mono text-text">{config.policy_contents_max_policies}</dd></div>
      <div className="sm:col-span-2">
        <dt className="text-text-secondary">Allowlist хостов</dt>
        <dd className="font-mono text-text">{config.allowlist_hosts.length ? config.allowlist_hosts.join(', ') : '—'}</dd>
      </div>
      <div className="sm:col-span-2">
        <dt className="text-text-secondary">Административные роли KSC</dt>
        <dd className="font-mono text-text">{config.admin_role_patterns.length ? config.admin_role_patterns.join(', ') : '—'}</dd>
      </div>
      <div className="sm:col-span-2">
        <dt className="mb-1 text-text-secondary">Ключевые компоненты</dt>
        <dd>
          <ul className="flex flex-col gap-0.5">
            {Object.entries(COMPONENT_LABELS).map(([code, label]) => (
              <li key={code} className="text-text"><span className="text-text-secondary">{label}:</span> <span className="font-mono">{(config.key_components[code] ?? []).join(', ') || '—'}</span></li>
            ))}
          </ul>
        </dd>
      </div>
    </dl>
  )
}

/** Пороги проверок — то, что в прототипе лежало в KSC_audit.config.json. */
export function RulesSection({ settings }: { settings: SettingsView }) {
  // Пороги аудитор читает: по ним считались находки, которые он разбирает.
  const { write } = useCan()
  const save = useSaveKscSettings()
  const [cfg, setCfg] = useState<KscConfig>(settings.config)
  const [dirty, setDirty] = useState(false)
  useEffect(() => { setCfg(settings.config); setDirty(false) }, [settings.config])
  const patch = (p: Partial<KscConfig>) => { setDirty(true); setCfg((c) => ({ ...c, ...p })) }
  const patchComponent = (code: string, values: string[]) => { setDirty(true); setCfg((c) => ({ ...c, key_components: { ...c.key_components, [code]: values } })) }

  return (
    <Section title="Пороги проверок" about="Пороги, по которым проверки решают, что агент молчит слишком долго, базы устарели, поиск давно не выполнялся или лицензия истекает. После изменения порогов пересчитайте снапшот на экране «Снапшоты».">
      {!write ? (
        <ReadOnlyView config={cfg} />
      ) : (
        <>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Агент молчит, дней" hint="по умолчанию 7"><input className={FIELD} type="number" min={1} value={cfg.agent_silent_days} onChange={(e) => patch({ agent_silent_days: Number(e.target.value) })} /></Field>
              <Field label="Базы устарели, дней" hint="по умолчанию 3"><input className={FIELD} type="number" min={1} value={cfg.bases_old_days} onChange={(e) => patch({ bases_old_days: Number(e.target.value) })} /></Field>
              <Field label="Нет полного поиска, дней" hint="по умолчанию 30"><input className={FIELD} type="number" min={1} value={cfg.fullscan_days} onChange={(e) => patch({ fullscan_days: Number(e.target.value) })} /></Field>
              <Field label="Лицензия истекает, дней" hint="по умолчанию 30"><input className={FIELD} type="number" min={1} value={cfg.license_days} onChange={(e) => patch({ license_days: Number(e.target.value) })} /></Field>
              <Field label="Провалы задачи → High, доля" hint="по умолчанию 0.2 (20% завершённых)"><input className={FIELD} type="number" min={0} max={1} step={0.05} value={cfg.task_failed_share} onChange={(e) => patch({ task_failed_share: Number(e.target.value) })} /></Field>
              <Field label="Задача обновления не запускалась, дней" hint="по умолчанию 7"><input className={FIELD} type="number" min={1} value={cfg.task_stale_days} onChange={(e) => patch({ task_stale_days: Number(e.target.value) })} /></Field>
              <Field label="Зависла перезагрузка, дней" hint="по умолчанию 7"><input className={FIELD} type="number" min={1} value={cfg.reboot_pending_days} onChange={(e) => patch({ reboot_pending_days: Number(e.target.value) })} /></Field>
              <Field label="Сертификат истекает, дней" hint="по умолчанию 60"><input className={FIELD} type="number" min={1} value={cfg.cert_days} onChange={(e) => patch({ cert_days: Number(e.target.value) })} /></Field>
              <Field label="Мало замков в политике, доля" hint="по умолчанию 0.5 — ниже порога POLICY_WEAK_LOCKS"><input className={FIELD} type="number" min={0} max={1} step={0.05} value={cfg.policy_lock_share} onChange={(e) => patch({ policy_lock_share: Number(e.target.value) })} /></Field>
              <Field label="Содержимое политик, максимум" hint="по умолчанию 200 — не больше стольки политик собирает онлайн-сборщик"><input className={FIELD} type="number" min={1} value={cfg.policy_contents_max_policies} onChange={(e) => patch({ policy_contents_max_policies: Number(e.target.value) })} /></Field>
            </div>
            <Field label="Allowlist хостов" hint="Маски имён хостов: test-*, *.lab.local — находки по ним понижаются до «справочно»">
              <textarea className={AREA} value={lines(cfg.allowlist_hosts)} onChange={(e) => patch({ allowlist_hosts: parseLines(e.target.value) })} />
            </Field>
            <Field label="Административные роли KSC" hint="Имена ролей (wstrRoleName/wstrRoleDisplayName), которые считаются административными — по одному на строку">
              <textarea className={AREA} value={lines(cfg.admin_role_patterns)} onChange={(e) => patch({ admin_role_patterns: parseLines(e.target.value) })} />
            </Field>
            <div className="sm:col-span-2">
              <div className="mb-1 text-xs font-medium text-text">Ключевые компоненты</div>
              <div className="grid gap-3 sm:grid-cols-2">
                {Object.entries(COMPONENT_LABELS).map(([code, label]) => (
                  <Field key={code} label={label} hint="Подстроки отображаемого имени, через запятую">
                    <input className={FIELD} value={csv(cfg.key_components[code] ?? [])} onChange={(e) => patchComponent(code, parseCsv(e.target.value))} />
                  </Field>
                ))}
              </div>
            </div>
          </div>
          <div className="mt-4 flex items-center gap-2 border-t border-grid pt-3">
            <Button variant="primary" onClick={() => save.mutate(cfg, { onSuccess: () => setDirty(false) })} loading={save.isPending} disabled={!dirty}><Save size={13} aria-hidden /> Сохранить</Button>
            <Button onClick={() => { setDirty(true); setCfg(settings.defaults) }}><RotateCcw size={13} aria-hidden /> Сбросить к умолчаниям</Button>
            {save.error && <span className="text-xs text-kind-1">{save.error instanceof ApiRequestError ? save.error.message : 'Не удалось сохранить'}</span>}
          </div>
        </>
      )}
    </Section>
  )
}
