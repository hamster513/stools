import type { ReactNode } from 'react'
import type { RiskCard } from '@/modules/vm/api/types'

function num(value: number) {
  return value.toLocaleString('ru-RU', { maximumFractionDigits: 2 })
}

export function SectionTitle({ children }: { children: ReactNode }) {
  return <div className="mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">{children}</div>
}

export function PriorityBreakdown({ r }: { r: RiskCard['risk'] }) {
  const blocks = Object.values(r.blocks)
  return (
    <>
      <SectionTitle>Приоритет исправления</SectionTitle>
      <code className="mb-1 block rounded border border-grid bg-app-bg px-2 py-1.5 font-mono text-[11px] text-text">
        {blocks.map(b => num(b.points)).join(' + ')} → {r.base_score}
        {r.floor > r.base_score && ` → ${r.computed_score} по правилу срочности`}
      </code>
      <p className="mb-3 text-[11px] text-text-secondary">Баллы от 0 до 100. High от {r.levels.high}, Critical от {r.levels.critical}. Это приоритет исправления, не вероятность инцидента.</p>
      <table className="mb-3 w-full text-xs">
        <tbody>
          {blocks.map(block => (
            <tr key={block.label} className="border-t border-grid/60 align-top">
              <td className="py-1.5 pr-2 font-medium text-text">{block.label}</td>
              <td className="py-1.5 pr-2 text-right font-mono tabular-nums text-text">{num(block.points)} / {block.maximum}</td>
              <td className="py-1.5 text-text-secondary">{block.source}{block.assumed && <span className="ml-1 text-risk-medium">· подстановка</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="mb-3 text-[11px] text-text-secondary">В блоке эксплуатации учитывается самый сильный сигнал: EPSS, эксплойт или KEV.</p>
      {r.rules.length > 0 && <div className="mb-3 rounded border border-risk-high/40 bg-risk-high/5 px-3 py-2 text-[11px] text-text-secondary">
        <SectionTitle>Правила срочности</SectionTitle>
        {r.rules.map(rule => <p key={rule.code}>{rule.label}: минимум {rule.minimum} баллов.</p>)}
      </div>}
      {r.missing.length > 0 && <p className="mb-3 rounded border border-risk-medium/40 bg-risk-medium/5 px-3 py-2 text-[11px] text-text-secondary">Нет данных: {r.missing.join(', ')}. Для неизвестных факторов использованы начальные значения модели.</p>}
      {r.computed_score !== r.score && <p className="mb-3 text-[11px] text-risk-medium">По текущим факторам: {r.computed_score}. В списке сохранён балл {r.score}; нужен пересчёт.</p>}
    </>
  )
}
