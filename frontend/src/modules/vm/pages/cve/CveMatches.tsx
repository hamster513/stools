import { useState } from 'react'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { Spinner } from '@/components/ui/Spinner'
import { Link } from '@/lib/router'
import { useCveHosts, useCveSoftware, type CveDetail } from '../../api/cve'
import { criticalities, riskColors } from './presentation'

export function CveMatches({ data }: { data: CveDetail }) {
  const [offset, setOffset] = useState(0), [softwareOffset, setSoftwareOffset] = useState(0)
  const hosts = useCveHosts(data.id, offset), software = useCveSoftware(data.id, softwareOffset)
  const h = offset === 0 ? data.matches : hosts.data
  const s = softwareOffset === 0 ? data.software_matches : software.data
  return <>
    <section className="space-y-3 rounded border border-grid bg-surface p-4"><div className="flex flex-wrap items-baseline justify-between gap-2"><h2 className="text-sm font-semibold">Хосты с уязвимостью · {data.matches.hosts_total}</h2>{data.matches.hosts_total > 0 && <p className="text-xs text-text-secondary">Фактический риск: <span className="font-mono text-text">{data.matches.risk_min}–{data.matches.risk_max} / 100</span></p>}</div>
      <p className="text-xs text-text-secondary">Находки загруженного сканирования MaxPatrol VM. Риск сохранён при последнем пересчёте; после изменения справочников или весов он может отличаться от нового потенциального диапазона.</p>
      {data.matches.hosts_total === 0 && <p className="text-sm">В загруженных данных сканирования хосты с этой уязвимостью не найдены.</p>}
      {offset > 0 && hosts.isPending && <Spinner />}{hosts.error && <ErrorState message={hosts.error.message} onRetry={() => hosts.refetch()} />}
      {!!h?.hosts.length && <div className="overflow-x-auto"><table className="w-full text-left text-xs"><thead className="border-b border-grid text-text-secondary"><tr>{['Хост', 'IP', 'Критичность хоста', 'Зона', 'Риск'].map(t => <th className="px-2 py-2 font-medium" key={t}>{t}</th>)}</tr></thead><tbody>{h.hosts.map(host => <tr className="border-b border-grid last:border-0 hover:bg-row-hover" key={host.id}><td className="px-2 py-2"><Link className="font-mono text-primary hover:underline" to={`/vm/vulns?host_id=${host.id}&cve=${host.identifier ?? data.id}&status=all`}>{host.hostname}</Link><span className="mt-1 block text-text-secondary">{host.os}</span></td><td className="px-2 py-2 font-mono">{host.ip || '—'}</td><td className="px-2 py-2">{criticalities[host.criticality] ?? 'Не задана'}</td><td className="px-2 py-2">{host.zone || '—'}</td><td className={`px-2 py-2 font-mono font-semibold ${riskColors[host.level]}`}>{host.risk}</td></tr>)}</tbody></table></div>}
      {data.matches.hosts_total > 50 && <div className="flex items-center gap-3 text-xs"><Button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset-50))}>Назад</Button><span>Страница {offset/50+1}</span><Button disabled={offset+50 >= data.matches.hosts_total} onClick={() => setOffset(offset+50)}>Далее</Button></div>}
    </section>
    {data.software_matches.total > 0 && <section className="space-y-3 rounded border border-grid bg-surface p-4"><h2 className="text-sm font-semibold">Совпадения по установленному ПО · {data.software_matches.total}</h2><p className="text-xs text-text-secondary">Текущая инвентаризация KSC и диапазоны версий NVD. Это сопоставление ПО, а не результат проверки эксплуатации.</p>
      {softwareOffset > 0 && software.isPending && <Spinner />}{software.error && <ErrorState message={software.error.message} onRetry={() => software.refetch()} />}
      <div className="divide-y divide-grid">{s?.items.map(item => <article className="space-y-1 py-2 text-xs" key={item.id}><p className="font-mono font-semibold">{item.hostname}</p><p>{item.software} · {item.version}</p><p className={item.state === 'affected' ? 'text-risk-high' : 'text-risk-medium'}>{item.state === 'affected' ? 'Версия входит в уязвимый диапазон' : 'Требуется проверка'}</p><p className="text-text-secondary">{item.reason}</p></article>)}</div>
      {data.software_matches.total > 50 && <div className="flex items-center gap-3 text-xs"><Button disabled={softwareOffset === 0} onClick={() => setSoftwareOffset(Math.max(0,softwareOffset-50))}>Назад</Button><span>Страница {softwareOffset/50+1}</span><Button disabled={softwareOffset+50 >= data.software_matches.total} onClick={() => setSoftwareOffset(softwareOffset+50)}>Далее</Button></div>}
    </section>}
  </>
}
