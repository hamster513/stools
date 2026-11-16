import { useEffect, useState } from 'react'
import { RefreshCw, Save } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useRecalculate, useSaveVmSettings } from '@/modules/vm/api/queries'
import type { SettingsView } from '@/modules/vm/api/types'
import { Button } from '@/components/ui/Button'
import { useCan } from '@/lib/can'
import { Section } from '@/platform/collector/ui'
import { NUM } from './ui'

const LABELS: Record<string, string> = { exploitation: 'Эксплуатация', severity: 'Последствия', exposure: 'Доступность', asset: 'Значимость актива' }

export function WeightsSection({ settings }: { settings: SettingsView }) {
  const { admin } = useCan()
  const save = useSaveVmSettings()
  const recalc = useRecalculate()
  const [threshold, setThreshold] = useState(settings.threshold)
  useEffect(() => { setThreshold(settings.threshold) }, [settings.threshold])
  const policy = settings.risk_model
  const error = save.error ?? recalc.error
  function submit() {
    save.mutate({
      connection: { host: settings.connection.host, api_token: '', verify_tls: settings.connection.verify_tls, os_exclude: settings.connection.os_exclude, pdql_extra: settings.connection.pdql_extra, limit: settings.connection.limit },
      weights: settings.weights, threshold,
    })
  }
  return (
    <Section id="weights" title="Скоринговая модель риска" about="Балл приоритета исправления от 0 до 100: сумма четырёх блоков и правила минимальной срочности. Балл не является вероятностью инцидента.">
      <div className="mb-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {Object.entries(policy.caps).map(([key, cap]) => <div key={key} className="rounded border border-grid bg-app-bg p-3"><div className="text-xs text-text-secondary">{LABELS[key]}</div><div className="mt-1 font-mono text-lg text-text">до {cap}</div></div>)}
      </div>
      <div className="mb-4 space-y-2 text-xs text-text-secondary">
        <p>Средний от {policy.levels.medium}, высокий от {policy.levels.high}, критический от {policy.levels.critical}. Веса и уровни заданы единой политикой модели.</p>
        <p>Эксплуатация: самый сильный сигнал. EPSS &lt;0,1% → 2; &lt;1% → 6; &lt;10% → 12; &lt;50% → 20; ≥50% → 30. Опубликованный эксплойт → 24; Metasploit good/great/excellent → 32; KEV → 40.</p>
        <p>Последствия: CVSS × 2,5. Доступность: сетевой вектор во внешней зоне → 20, во внутренней → 10, неизвестная зона → 12; смежная сеть → 8; локальный или физический вектор → 4.</p>
        <p>Значимость актива: Critical → 15, High → 12, Medium → 8, Low → 4; конфиденциальные данные +2 с пределом 15.</p>
        <p>Нет данных: EPSS → 8, CVSS → 12,5, вектор атаки → 12, критичность → 8. Подстановки показаны в карточке; отсутствие разметки не означает внутреннюю зону.</p>
      </div>
      <div className="mb-4 space-y-1 rounded border border-risk-high/40 bg-risk-high/5 p-3 text-xs text-text">
        <p>KEV — минимум {policy.floors.kev_minimum}, не ниже High.</p>
        <p>Сетевой KEV во внешней зоне — минимум {policy.floors.kev_network_external_zone}, Critical.</p>
        <p>Готовый Metasploit + CVSS ≥9 + критичный актив — минимум {policy.floors.ready_exploit_critical_asset}, Critical.</p>
      </div>
      <div className="mb-2 flex flex-wrap items-center gap-3">
        <label htmlFor="risk-threshold" className="text-xs text-text">Порог «требует действия»</label>
        <input id="risk-threshold" className={NUM} type="number" min={0} max={100} step={1} value={threshold} onChange={e => setThreshold(Number(e.target.value))} disabled={!admin} />
        <span className="text-[11px] text-text-secondary">Отдельный порог на обзоре и в карточках; не меняет уровни High и Critical.</span>
      </div>
      {admin && <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-grid pt-3">
        <Button variant="primary" onClick={submit} loading={save.isPending} disabled={threshold === settings.threshold || !Number.isInteger(threshold) || threshold < 0 || threshold > 100}><Save size={13} aria-hidden /> Сохранить порог</Button>
        <Button onClick={() => recalc.mutate()} loading={recalc.isPending}><RefreshCw size={13} aria-hidden /> Пересчитать риски</Button>
        {recalc.data && <span className="text-xs text-text-secondary">Пересчёт запущен, задача #{recalc.data.job_id}</span>}
        {error && <span className="text-xs text-kind-1">{error instanceof ApiRequestError ? error.message : 'Не удалось выполнить действие'}</span>}
      </div>}
    </Section>
  )
}
