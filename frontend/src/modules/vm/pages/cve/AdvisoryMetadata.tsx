import type { CveDetail, GhsaPackage } from '../../api/cve'
import { Link } from '@/lib/router'

function rangeText(range: GhsaPackage['ranges'][number]) {
  const labels: Record<string, string> = { introduced: 'начиная с', fixed: 'исправлено в', last_affected: 'последняя уязвимая', limit: 'до, не включая' }
  return range.events.map(event => Object.entries(event).map(([key, value]) => key === 'introduced' && value === '0' ? 'без нижней границы' : `${labels[key] ?? key} ${value}`).join(', ')).join('; ')
}
export function AdvisoryMetadata({ data }: { data: CveDetail }) {
  return <>
    {!!data.aliases?.length && <div className="flex flex-wrap items-center gap-2 text-xs"><span className="text-text-secondary">Связанные идентификаторы:</span>{data.aliases.map(id => <Link key={id} to={`/vm/cve?q=${encodeURIComponent(id)}`} className="rounded border border-grid px-2 py-1 font-mono text-primary hover:underline">{id}</Link>)}</div>}
    {data.withdrawn && <p className="rounded border border-risk-medium bg-app-bg p-3 text-xs text-risk-medium">Запись GitHub отозвана {new Date(data.withdrawn).toLocaleDateString('ru-RU')}. Она сохранена для проверки истории; новые связи по её алиасам не подтверждаются.</p>}
    {!!data.advisories?.length && <div className="space-y-1 text-xs">{data.advisories.map(a => <p key={a.id}><a href={a.url} target="_blank" rel="noopener noreferrer" className="font-mono text-primary hover:underline">{a.id}</a><span className="ml-2 text-text-secondary">{a.withdrawn ? 'Отозвана' : a.reviewed ? 'Проверена GitHub' : 'Не проверена GitHub'}</span></p>)}</div>}
    {!!data.packages?.length && <details className="text-xs" open={data.packages.length <= 3}><summary className="cursor-pointer font-semibold">Затронутые пакеты и версии · {data.packages.length}</summary><div className="mt-3 divide-y divide-grid">{data.packages.map((p, i) => <div className="space-y-1 py-2" key={`${p.ghsa_id}:${i}`}><p className="break-words"><span className="mr-2 rounded bg-app-bg px-1.5 py-0.5 font-mono">{p.ecosystem}</span><span className="font-semibold">{p.name}</span></p>{p.purl && <p className="break-all font-mono text-text-secondary">{p.purl}</p>}{p.ranges.map((r, j) => <p key={j} className="break-words">{rangeText(r)} <span className="text-text-secondary">({r.type})</span></p>)}{!!p.fixed_versions.length && <p className="break-words text-risk-low">Исправленные версии: {p.fixed_versions.join(', ')}</p>}{!!p.versions.length && <details><summary className="cursor-pointer text-text-secondary">Перечисленные уязвимые версии ({p.versions.length})</summary><p className="mt-1 break-words font-mono">{p.versions.join(', ')}</p></details>}</div>)}</div><p className="mt-2 text-text-secondary">Данные GitHub Advisory Database. Похожее название установленного ПО само по себе не подтверждает совпадение пакета или уязвимой версии.</p></details>}
  </>
}
