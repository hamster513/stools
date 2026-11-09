import { runStates, runTone } from './runStatus'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { TREND_BASE, when } from '../../../api/trends'
import { useMonitoring, type SourceRun } from '../../../api/trendMonitoring'
import { SourcePreview } from './SourcePreview'
export function RunHistory() {
  const [job, setJob] = useState(''); const monitoring = useMonitoring()
  const runs = useQuery({ queryKey: ['vm-trends', 'runs'], queryFn: () => api.get<{ items: SourceRun[] }>(TREND_BASE + '/runs'), refetchInterval: 5000 })
  return <div className="space-y-3"><h3 className="font-semibold">Очереди и история проверок</h3>{monitoring.data && <><p className="text-sm">Ожидает обогащения: {monitoring.data.pending.enrichment ?? 0} · поиска PoC: {monitoring.data.pending.poc_search ?? 0} · проверки репозитория: {monitoring.data.pending.poc_validate ?? 0}. Счётчики включают отложенное обновление кэша.</p><details><summary>Состояния поиска PoC</summary>{monitoring.data.poc_search.map(row => <p className={`text-xs ${row.error ? 'text-kind-1' : row.total != null ? 'text-kind-accepted' : 'text-text-secondary'}`} key={row.id}>{row.cve_id} · {when(row.checked_at)} · {row.error || (row.total == null ? 'ожидает' : `найдено ${row.total}`)}{row.truncated ? ' · выдача ограничена' : ''} · следующая {when(row.next_attempt)}</p>)}</details></>}
    {job && <SourcePreview jobId={job} onJob={setJob} close={() => setJob('')} />}{runs.error && <p role="alert" className="text-kind-1">{runs.error.message}</p>}
    <div className="overflow-auto"><table className="w-full text-left text-xs"><thead className="bg-surface text-[11px] font-semibold tracking-wide text-text-secondary uppercase"><tr><th>Начало</th><th>Источник</th><th>Результат</th><th>Этап</th><th>Получено / новых</th><th /></tr></thead><tbody>{runs.data?.items.map(row => <tr key={row.id} className="border-t border-grid"><td className="p-2">{when(row.created_at)}</td><td className="max-w-40 break-all p-2 text-xs">{row.source_id}</td><td className={`p-2 ${runTone(row.state, row.error)}`}>{runStates[row.state] ?? row.state}<p className="text-xs">{row.error}</p></td><td>{row.stage}</td><td>{row.counters?.fetched ?? 0} / {row.counters?.new_versions ?? 0}</td><td><Button className="px-2 py-1 text-xs" onClick={() => setJob(row.id)}>Подробнее</Button></td></tr>)}</tbody></table></div>
  </div>
}
