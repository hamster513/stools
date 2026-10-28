import type { ReactNode } from 'react'
import type { Factor, RiskCard } from '@/modules/vm/api/types'
import { cn } from '@/lib/cn'

/** Общие части дроверов расчёта риска: хоста (RiskDrawer) и образа (ImageRiskDrawer). */

function num(v: number): string {
  // Значащие цифры, а не знаки после запятой: типичный EPSS 0,0004 иначе показывался бы как «0».
  return v.toLocaleString('ru-RU', { maximumSignificantDigits: 3 })
}

/** Члены формулы — ровно два знака, как в строке `0,82 × 0,98 × 1,00 × 100 = 81`. */
function num2(v: number): string {
  return v.toLocaleString('ru-RU', { minimumFractionDigits: 2, maximumFractionDigits: 2 })
}

export function SectionTitle({ children }: { children: ReactNode }) {
  return <div className="mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">{children}</div>
}

export function FactorRow({ label, f, loaded, total }: { label: string; f: Factor; loaded?: string | null; total?: boolean }) {
  return (
    <tr className="border-t border-grid/60 align-top">
      <td className={cn('py-1.5 pr-2', total ? 'font-medium text-text' : 'text-text-secondary')}>{label}</td>
      <td className={cn('py-1.5 pr-2 text-right font-mono tabular-nums', f.substituted ? 'text-risk-medium' : 'text-text')}>{num(f.value)}</td>
      <td className="py-1.5 text-text-secondary">
        {f.source}
        {f.substituted && <span className="ml-1 text-[10px] text-risk-medium">подставлено</span>}
        {loaded && <span className="ml-1 text-[10px]">· справочник от {new Date(loaded).toLocaleDateString('ru-RU')}</span>}
      </td>
    </tr>
  )
}

/** Заголовок «Формула», строка с числами и подпись; `valueLabel` — как назван третий член («ценность хоста»). */
export function FormulaBlock({ r, valueLabel }: { r: RiskCard['risk']; valueLabel: string }) {
  return (
    <>
      <SectionTitle>Формула</SectionTitle>
      <code className="mb-1 block rounded border border-grid bg-app-bg px-2 py-1.5 font-mono text-[11px] text-text">
        {num2(r.likelihood.value)} × {num2(r.severity.value)} × {num2(r.value.value)} × 100 = {r.score}
      </code>
      <p className="mb-3 text-[11px] text-text-secondary">
        вероятность эксплуатации × тяжесть × {valueLabel}
        {/* Балл — сохранённый при последнем пересчёте, части — по текущим весам: после смены весов они расходятся до пересчёта.
            Порядок умножения и округление — как в SQL пересчёта, иначе половинки давали бы ложное расхождение. */}
        {Math.floor(r.likelihood.value * r.severity_parts.cvss.value * r.severity_parts.reach.value * r.value.value * 100 + 0.5) !== r.score && ' · части посчитаны по текущим весам, балл — по последнему пересчёту'}
      </p>
    </>
  )
}
