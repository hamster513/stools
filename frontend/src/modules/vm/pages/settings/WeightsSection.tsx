import { useEffect, useState } from 'react'
import { RotateCcw, Save } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useRecalculate, useSaveVmSettings } from '@/modules/vm/api/queries'
import type { SettingsView, Weights } from '@/modules/vm/api/types'
import { Button } from '@/components/ui/Button'
import { useCan } from '@/lib/can'
import { NUM, Section } from './ui'

function Table({ title, rows, labels, onChange }: { title: string; rows: Record<string, number>; labels?: Record<string, string>; onChange: (k: string, v: number) => void }) {
  // Веса аудитор читает: без них непонятно, из чего сложился балл.
  const { write } = useCan()
  return (
    <div>
      <div className="mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">{title}</div>
      <table className="text-xs">
        <tbody>
          {Object.entries(rows).map(([k, v]) => (
            <tr key={k}>
              <td className="py-0.5 pr-3 text-text-secondary">{labels?.[k] ?? k}</td>
              <td className="py-0.5"><input className={NUM} type="number" step={0.05} value={v} onChange={(e) => onChange(k, Number(e.target.value))} aria-label={`${title}: ${labels?.[k] ?? k}`} disabled={!write} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

const YESNO = { yes: 'есть', no: 'нет' }
const INET = { yes: 'доступен', no: 'недоступен' }

/** Веса формулы. Сохранение ставит задачу пересчёта: он идёт секунды, а не часы. */
export function WeightsSection({ settings }: { settings: SettingsView }) {
  const { write } = useCan()
  const save = useSaveVmSettings()
  const recalc = useRecalculate()
  const [w, setW] = useState<Weights>(settings.weights)
  const [threshold, setThreshold] = useState(settings.threshold)
  const [dirty, setDirty] = useState(false)
  useEffect(() => { setW(settings.weights); setThreshold(settings.threshold); setDirty(false) }, [settings.weights, settings.threshold])

  function set(path: (draft: Weights) => Record<string, number>, k: string, v: number) {
    setDirty(true)
    setW((prev) => {
      const next: Weights = JSON.parse(JSON.stringify(prev))
      path(next)[k] = v
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
      { connection: { host: settings.connection.host, username: settings.connection.username, password: '', client_secret: '', verify_tls: settings.connection.verify_tls, os_exclude: settings.connection.os_exclude, pdql_extra: settings.connection.pdql_extra, limit: settings.connection.limit }, weights: w, threshold },
      { onSuccess: () => { setDirty(false); recalc.mutate() } },
    )
  }

  return (
    <Section
      title="Формула риска"
      about={<>Risk = EPSS × (CVSS ÷ 10) × Impact × CVE_param × ExDB_param × MSF_param; балл = min(1, Risk) × 100. Impact — сумма трёх слагаемых, CVE_param — произведение множителей CVSS v3 (или v2, если v3 нет), ExDB и MSF — по самому весомому эксплойту и модулю. Нет данных — множитель 1, нет EPSS — 0.5. Значения по умолчанию — из документированной формулы первой итерации.</>}
    >
      <div className="mb-4 flex items-center gap-3">
        <label className="text-xs text-text">Порог риска</label>
        <input className={NUM} type="number" min={0} max={100} value={threshold} onChange={(e) => { setDirty(true); setThreshold(Number(e.target.value)) }} aria-label="Порог риска" disabled={!write} />
        <span className="text-[11px] text-text-secondary">выше порога — «требует действия» на обзоре и в карточке</span>
      </div>
      <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
        <Table title="Impact: критичность" rows={w.impact.criticality} onChange={(k, v) => set((d) => d.impact.criticality, k, v)} />
        <div className="flex flex-col gap-4">
          <Table title="Impact: конф. данные" rows={w.impact.confidential} labels={YESNO} onChange={(k, v) => set((d) => d.impact.confidential, k, v)} />
          <Table title="Impact: интернет" rows={w.impact.internet} labels={INET} onChange={(k, v) => set((d) => d.impact.internet, k, v)} />
        </div>
        <div className="flex flex-col gap-4">
          <Table title="CVSS v3: Attack Vector" rows={w.cvss_v3.av} onChange={(k, v) => set((d) => d.cvss_v3.av, k, v)} />
          <Table title="CVSS v3: Privileges" rows={w.cvss_v3.pr} onChange={(k, v) => set((d) => d.cvss_v3.pr, k, v)} />
          <Table title="CVSS v3: User Interaction" rows={w.cvss_v3.ui} onChange={(k, v) => set((d) => d.cvss_v3.ui, k, v)} />
        </div>
        <div className="flex flex-col gap-4">
          <Table title="CVSS v2: Access Vector" rows={w.cvss_v2.av} onChange={(k, v) => set((d) => d.cvss_v2.av, k, v)} />
          <Table title="CVSS v2: Complexity" rows={w.cvss_v2.ac} onChange={(k, v) => set((d) => d.cvss_v2.ac, k, v)} />
          <Table title="CVSS v2: Authentication" rows={w.cvss_v2.au} onChange={(k, v) => set((d) => d.cvss_v2.au, k, v)} />
        </div>
        <Table title="ExploitDB: тип" rows={w.exploitdb} onChange={(k, v) => set((d) => d.exploitdb, k, v)} />
        <Table title="Metasploit: ранг" rows={w.msf} onChange={(k, v) => set((d) => d.msf, k, v)} />
      </div>
      {write && (
        <div className="mt-4 flex items-center gap-2 border-t border-grid pt-3">
          <Button variant="primary" onClick={submit} loading={save.isPending} disabled={!dirty}><Save size={13} aria-hidden /> Сохранить и пересчитать</Button>
          <Button onClick={reset}><RotateCcw size={13} aria-hidden /> По умолчанию</Button>
          {save.error && <span className="text-xs text-kind-1">{save.error instanceof ApiRequestError ? save.error.message : 'Не удалось сохранить'}</span>}
          {recalc.data && !dirty && <span className="text-xs text-text-secondary">пересчёт запущен, задача #{recalc.data.job_id}</span>}
        </div>
      )}
    </Section>
  )
}
