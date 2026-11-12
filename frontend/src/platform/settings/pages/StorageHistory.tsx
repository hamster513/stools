import { useState } from 'react'
import { bytes, growth, historyValue, type HistoryPoint, type StorageModule } from '../storage'
import { FIELD } from '@/components/ui/Field'

export function StorageHistory({ points, modules, tz }: { points: HistoryPoint[]; modules: StorageModule[]; tz: string }) {
  const [module, setModule] = useState('all')
  const date = (iso: string) => new Date(iso).toLocaleString('ru-RU', { timeZone: tz, dateStyle: 'short', timeStyle: 'short' })
  const values = points.map(p => historyValue(p, module))
  const max = Math.max(1, ...values.map(v => v?.total_bytes ?? 0))
  const delta = growth(points, module)
  const times = points.map(p => new Date(p.measured_at).getTime())
  const span = (times.at(-1) ?? 0) - (times[0] ?? 0)
  const x = (i: number) => span > 0 ? 80 + (times[i] - times[0]) / span * 720 : 440
  const y = (n: number) => 215 - n / max * 175
  return <div className="space-y-3">
    <label className="block max-w-sm text-sm">Объём на графике<select aria-label="Объём на графике" className={`${FIELD} mt-1`} value={module} onChange={e => setModule(e.target.value)}><option value="all">Всё хранилище</option>{modules.map(m => <option key={m.id} value={m.id}>{m.title}</option>)}</select></label>
    {points.length === 0 ? <p className="text-sm text-text-secondary">За выбранный период замеров ещё нет.</p> : <>
      <p className="text-sm">{date(points[0].measured_at)} — {date(points[points.length - 1].measured_at)} · Изменение: <strong>{delta == null ? 'недостаточно сопоставимых замеров' : `${delta > 0 ? '+' : ''}${bytes(delta)}`}</strong></p>
      <svg viewBox="0 0 880 255" role="img" aria-label="История объёма хранилища. Точные значения доступны в таблице ниже." className="w-full rounded border border-grid bg-surface">
        <line x1="80" y1="215" x2="800" y2="215" className="stroke-border" />
        <text x="12" y="44" fontSize="12" className="fill-text-secondary">{bytes(max)}</text><text x="12" y="219" fontSize="12" className="fill-text-secondary">0 Б</text>
        {points.map((p, i) => {
          const value = values[i], previous = values[i - 1]
          if (!value?.complete || value.total_bytes == null) return null
          const previousBytes = previous?.total_bytes
          const join = previous?.complete && previousBytes != null && (module !== 'all' || points[i - 1].coverage === p.coverage)
          return <g key={p.measured_at}>{join && <line x1={x(i-1)} y1={y(previousBytes)} x2={x(i)} y2={y(value.total_bytes)} className="stroke-primary" strokeWidth="2" />}<circle cx={x(i)} cy={y(value.total_bytes)} r="4" className="fill-primary" tabIndex={0} aria-label={`${date(p.measured_at)}: ${bytes(value.total_bytes)}`}><title>{date(p.measured_at)}: {bytes(value.total_bytes)}</title></circle></g>
        })}
        <text x="80" y="243" fontSize="12" className="fill-text-secondary">{date(points[0].measured_at).split(',')[0]}</text><text x="800" y="243" textAnchor="end" fontSize="12" className="fill-text-secondary">{date(points[points.length - 1].measured_at).split(',')[0]}</text>
      </svg>
      <p className="text-xs text-text-secondary">Последний замер каждого дня, часовой пояс {tz}. Пропуски не заменяются нулями; неполные замеры и разный состав источников не соединяются линией.</p>
      <details className="rounded border border-grid p-3"><summary className="cursor-pointer text-sm font-medium">Точные значения ({points.length})</summary><div className="mt-3 max-h-72 overflow-auto"><table className="w-full text-left text-sm"><thead><tr><th className="p-2">Дата замера</th><th className="p-2">Объём</th><th className="p-2">Полнота</th></tr></thead><tbody>{points.map((p, i) => <tr key={p.measured_at} className="border-t border-grid"><td className="p-2">{date(p.measured_at)}</td><td className="p-2 tabular-nums">{values[i]?.total_bytes != null && !values[i].complete ? '≥ ' : ''}{bytes(values[i]?.total_bytes)}</td><td className="p-2">{values[i]?.total_bytes == null ? 'Нет данных' : values[i].complete ? 'Полный замер' : 'Неполный замер'}</td></tr>)}</tbody></table></div></details>
    </>}
  </div>
}
