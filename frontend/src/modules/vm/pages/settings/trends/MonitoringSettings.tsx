import { useState } from 'react'
import { api } from '@/api/client'
import { useCan } from '@/lib/can'
import { Button } from '@/components/ui/Button'
import { Link } from '@/lib/router'
import { TREND_BASE, useTrendMutation } from '../../../api/trends'
import { useMonitoring, useProfiles, type MonitoringOptions } from '../../../api/trendMonitoring'
export function MonitoringSettings() {
  const data = useMonitoring(); const profiles = useProfiles()
  return <div className="space-y-4">{data.error && <p role="alert">{data.error.message}</p>}{data.data && <SettingsForm initial={data.data.settings} />}
    <p className="text-sm">Опрос источников выполняет сборщик. Получение данных STools — отдельная задача <Link className="underline" to="/settings/schedules">в общем расписании</Link>.</p>
    <p className="text-sm">PoC проверяются статически, без выполнения кода. Поиск повторяется не чаще 6 часов; не более 20 кандидатов на CVE. При ограничении API очередь сохраняется.</p>
    <details><summary>Маршруты сборщика</summary>{profiles.data?.map(p => <p className="text-sm" key={p.name}>{p.name}: {p.ready ? p.route === 'proxy' ? 'через прокси' : 'прямой доступ' : 'недоступен'}</p>)}<p className="text-xs">Адреса и пароли прокси, токены GitHub и CA задаются на сборщике. Для источника можно выбрать готовый профиль.</p></details>
  </div>
}
function SettingsForm({ initial }: { initial: MonitoringOptions }) {
  const { admin } = useCan(); const [form, setForm] = useState(initial)
  const save = useTrendMutation(() => api.put(TREND_BASE + '/monitoring/settings', form))
  return <section className="space-y-3"><p className="text-sm text-text-secondary">Общие настройки этого сборщика для всех потребителей.</p><fieldset disabled={!admin || save.isPending} className="space-y-2">{(['collection_enabled', 'enrichment_enabled', 'poc_enabled'] as const).map((key, i) => <label key={key} className="flex items-center gap-2"><input type="checkbox" checked={form[key]} onChange={e => setForm({ ...form, [key]: e.target.checked })} />{['Автоматический опрос включённых источников', 'Обогащение публичных CVE (NVD / CNA / EPSS)', 'Поиск и статическая проверка GitHub PoC'][i]}</label>)}</fieldset>{admin && <Button disabled={save.isPending} onClick={() => save.mutate()}>Сохранить мониторинг</Button>}{save.isSuccess && <p role="status">Сохранено</p>}{save.error && <p role="alert">{save.error.message}</p>}</section>
}
