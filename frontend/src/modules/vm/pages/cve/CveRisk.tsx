import type { CveDetail, RiskProfile } from '../../api/cve'
import { criticalities, riskColors } from './presentation'

const assumptions: Record<string, string> = { epss: 'EPSS не получен — применено значение из настроек', cvss: 'CVSS не получен — применено значение из настроек', reach: 'Вектор атаки неизвестен — достижимость взята из настроек', kev: 'Нет данных об известной эксплуатации для этого идентификатора' }
function Profile({ title, value }: { title: string; value: RiskProfile }) {
  return <div className="rounded border border-grid bg-app-bg p-3 text-xs"><p className="mb-2 font-semibold">{title}: {value.score} / 100</p><dl className="grid grid-cols-2 gap-x-3 gap-y-1 text-text-secondary"><dt>Критичность хоста</dt><dd className="text-text">{criticalities[value.criticality] ?? value.criticality}</dd><dt>Доступ из интернета</dt><dd className="text-text">{value.internet ? 'Есть' : 'Нет'}</dd><dt>Конфиденциальные данные</dt><dd className="text-text">{value.confidential ? 'Есть' : 'Нет'}</dd></dl></div>
}
export function CveRisk({ data }: { data: CveDetail }) {
  const r = data.risk
  return <section className="space-y-3 rounded border border-grid bg-surface p-4" aria-label="Потенциальный риск">
    <div className="flex flex-wrap items-baseline justify-between gap-2"><h2 className="text-sm font-semibold">Потенциальный риск</h2><p className="font-mono text-xl font-semibold"><span className={riskColors[r.min_level]}>{r.min}</span>–<span className={riskColors[r.max_level]}>{r.max}</span><span className="ml-2 text-xs font-normal text-text-secondary">из 100</span></p></div>
    <p className="text-xs text-text-secondary">Диапазон по {r.scenario_count} вариантам характеристик хоста и текущим весам формулы VM. Оценка для случая, если уязвимость присутствует на хосте; CVSS описывает критичность самой уязвимости.</p>
    <div className="grid gap-3 xl:grid-cols-2"><Profile title="Минимум" value={r.min_profile} /><Profile title="Максимум" value={r.max_profile} /></div>
    {r.assumptions.length > 0 && <details className="text-xs text-risk-medium"><summary className="cursor-pointer">В расчёте есть недостающие данные ({r.assumptions.length})</summary><ul className="mt-2 list-inside list-disc space-y-1">{r.assumptions.map(a => <li key={a}>{assumptions[a] ?? `Подстановка формулы: ${a}`}</li>)}</ul></details>}
  </section>
}
