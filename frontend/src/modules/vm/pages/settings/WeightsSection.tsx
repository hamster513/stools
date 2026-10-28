import { useEffect, useState } from 'react'
import { RotateCcw, Save } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useRecalculate, useSaveVmSettings } from '@/modules/vm/api/queries'
import type { SettingsView, Weights } from '@/modules/vm/api/types'
import { Button } from '@/components/ui/Button'
import { useCan } from '@/lib/can'
import { Section } from '@/platform/collector/ui'
import { NUM } from './ui'

function Table({ title, rows, labels, onChange }: { title: string; rows: Record<string, number>; labels?: Record<string, string>; onChange: (k: string, v: number) => void }) {
  // Веса аудитор читает: без них непонятно, из чего сложился балл.
  const { admin } = useCan()
  return (
    <div>
      <div className="mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">{title}</div>
      <table className="text-xs">
        <tbody>
          {Object.entries(rows).map(([k, v]) => (
            <tr key={k}>
              <td className="py-0.5 pr-3 text-text-secondary">{labels?.[k] ?? k}</td>
              <td className="py-0.5"><input className={NUM} type="number" step={0.05} value={v} onChange={(e) => onChange(k, Number(e.target.value))} aria-label={`${title}: ${labels?.[k] ?? k}`} disabled={!admin} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

const REACH = { network_internet: 'сеть, хост из интернета', network_internal: 'сеть, хост внутри', adjacent: 'соседняя сеть', local: 'локально / физически' }

function Scalar({ label, value, onChange, step = 0.05 }: { label: string; value: number; onChange: (v: number) => void; step?: number }) {
  const { admin } = useCan()
  return (
    <label className="flex items-center justify-between gap-3 py-0.5 text-xs">
      <span className="text-text-secondary">{label}</span>
      <input className={NUM} type="number" step={step} value={value} onChange={(e) => onChange(Number(e.target.value))} aria-label={label} disabled={!admin} />
    </label>
  )
}

/** Веса формулы. Сохранение ставит задачу пересчёта: он идёт секунды, а не часы. */
export function WeightsSection({ settings }: { settings: SettingsView }) {
  const { admin } = useCan()
  const save = useSaveVmSettings()
  const recalc = useRecalculate()
  const [w, setW] = useState<Weights>(settings.weights)
  const [threshold, setThreshold] = useState(settings.threshold)
  const [dirty, setDirty] = useState(false)
  useEffect(() => { setW(settings.weights); setThreshold(settings.threshold); setDirty(false) }, [settings.weights, settings.threshold])

  // Черновик меняется копией: вложенные словари общие с данными запроса, мутировать их нельзя.
  function edit(change: (draft: Weights) => void) {
    setDirty(true)
    setW((prev) => {
      const next: Weights = JSON.parse(JSON.stringify(prev))
      change(next)
      return next
    })
  }
  function reset() {
    setDirty(true)
    setW(JSON.parse(JSON.stringify(settings.defaults.weights)))
    setThreshold(settings.defaults.threshold)
  }
  function submit() {
    save.mutate(
      { connection: { host: settings.connection.host, api_token: '', verify_tls: settings.connection.verify_tls, os_exclude: settings.connection.os_exclude, pdql_extra: settings.connection.pdql_extra, limit: settings.connection.limit }, weights: w, threshold },
      { onSuccess: () => { setDirty(false); recalc.mutate() } },
    )
  }

  const { medium, high, critical } = w.levels
  // Та же проверка, что на сервере (422): не отправлять заведомо неверные пороги.
  const levelsOk = [medium, high, critical].every(Number.isInteger) && 0 < medium && medium < high && high < critical && critical <= 100

  return (
    <Section
      id="weights"
      title="Формула риска"
      about={<>Risk = round(100 × L × S × V). L — вероятность эксплуатации: 1, если CVE в каталоге CISA KEV, иначе 1 − (1 − EPSS) × (1 − p_exdb[тип лучшего эксплойта]) × (1 − p_msf[лучший ранг модуля]); нет EPSS — «EPSS по умолчанию» с пометкой «не измерено», нет эксплойта или модуля — 0. S — тяжесть: CVSS ÷ 10 (v3, иначе v2; нет CVSS — «CVSS по умолчанию») × достижимость по вектору атаки CVE и доступу хоста из интернета (нет метрик — «достижимость без метрик»). V — ценность хоста: критичность + бонус за конф. данные + бонус за интернет, не больше 1; зона не размечена — обе галочки «нет». Уровень вычисляется из балла по порогам при чтении: пороги меняются без пересчёта.</>}
    >
      <div className="mb-4 flex items-center gap-3">
        <label htmlFor="risk-threshold" className="text-xs text-text">Порог риска</label>
        <input id="risk-threshold" className={NUM} type="number" min={0} max={100} value={threshold} onChange={(e) => { setDirty(true); setThreshold(Number(e.target.value)) }} aria-label="Порог риска" disabled={!admin} />
        <span className="text-[11px] text-text-secondary">выше порога — «требует действия» на обзоре и в карточке</span>
      </div>
      <div className="mb-4">
        <div className="mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">Уровни</div>
        <div className="flex flex-wrap items-center gap-2 text-xs text-text-secondary">
          {/* Нижние границы по баллу; ниже «среднего» — низкий. */}
          средний ≥ <input className={NUM} type="number" step={1} min={1} max={100} value={medium} onChange={(e) => edit((d) => { d.levels.medium = Number(e.target.value) })} aria-label="Уровни: средний от" disabled={!admin} />
          высокий ≥ <input className={NUM} type="number" step={1} min={1} max={100} value={high} onChange={(e) => edit((d) => { d.levels.high = Number(e.target.value) })} aria-label="Уровни: высокий от" disabled={!admin} />
          критический ≥ <input className={NUM} type="number" step={1} min={1} max={100} value={critical} onChange={(e) => edit((d) => { d.levels.critical = Number(e.target.value) })} aria-label="Уровни: критический от" disabled={!admin} />
          {!levelsOk && <span className="text-kind-1">нужны целые: 0 &lt; средний &lt; высокий &lt; критический ≤ 100</span>}
        </div>
      </div>
      <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
        <div className="flex flex-col gap-0.5">
          <div className="mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">Подстановки и бонусы</div>
          <Scalar label="EPSS по умолчанию" value={w.prior_epss} onChange={(v) => edit((d) => { d.prior_epss = v })} />
          <Scalar label="CVSS по умолчанию" value={w.cvss_missing} onChange={(v) => edit((d) => { d.cvss_missing = v })} />
          <Scalar label="достижимость без метрик" value={w.reach_unknown} onChange={(v) => edit((d) => { d.reach_unknown = v })} />
          <Scalar label="бонус за конф. данные" value={w.value.conf_bonus} onChange={(v) => edit((d) => { d.value.conf_bonus = v })} />
          <Scalar label="бонус за интернет" value={w.value.inet_bonus} onChange={(v) => edit((d) => { d.value.inet_bonus = v })} />
        </div>
        <Table title="Эксплойт: вероятность по типу" rows={w.p_exdb} onChange={(k, v) => edit((d) => { d.p_exdb[k] = v })} />
        <Table title="Metasploit: вероятность по рангу" rows={w.p_msf} onChange={(k, v) => edit((d) => { d.p_msf[k] = v })} />
        <div className="flex flex-col gap-4">
          <Table title="Достижимость" rows={w.reach} labels={REACH} onChange={(k, v) => edit((d) => { d.reach[k as keyof Weights['reach']] = v })} />
          <Table title="Ценность: критичность" rows={w.value.criticality} labels={{ None: 'не задана' }} onChange={(k, v) => edit((d) => { d.value.criticality[k] = v })} />
        </div>
      </div>
      {admin && (
        <div className="mt-4 flex items-center gap-2 border-t border-grid pt-3">
          <Button variant="primary" onClick={submit} loading={save.isPending} disabled={!dirty || !levelsOk}><Save size={13} aria-hidden /> Сохранить и пересчитать</Button>
          <Button onClick={reset}><RotateCcw size={13} aria-hidden /> По умолчанию</Button>
          {save.error && <span className="text-xs text-kind-1">{save.error instanceof ApiRequestError ? save.error.message : 'Не удалось сохранить'}</span>}
          {recalc.data && !dirty && <span className="text-xs text-text-secondary">пересчёт запущен, задача #{recalc.data.job_id}</span>}
        </div>
      )}
    </Section>
  )
}
