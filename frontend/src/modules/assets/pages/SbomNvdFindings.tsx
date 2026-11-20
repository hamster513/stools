import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api, buildQuery, errorText } from '@/api/client'
import { ErrorState } from '@/components/ui/ErrorState'
import { Spinner } from '@/components/ui/Spinner'
import { Link } from '@/lib/router'
import { SoftwarePager } from './software/SoftwarePager'

interface NvdPage {
  ready: boolean
  examined: number
  affected: number
  unknown: number
  items: { cve_id: string; state: 'affected' | 'unknown'; reason: string; evidence: string[] }[]
}

export function SbomNvdFindings({ url, revision }: { url: string; revision: string | null }) {
  const [offset, setOffset] = useState(0)
  const limit = 10
  const query = useQuery<NvdPage>({
    queryKey: ['sbom-component-nvd', url, revision, offset],
    queryFn: ({ signal }) => api.get(url + buildQuery({ offset, limit }), { signal }),
  })
  if (query.isPending) return <Spinner />
  if (query.isError) return <ErrorState message={errorText(query.error, 'Не удалось проверить версию по NVD') ?? ''} onRetry={() => query.refetch()} />
  const { ready, examined, affected, unknown, items } = query.data
  return <div className="space-y-2">
    {!ready && <p className="text-risk-medium">Локальная база NVD с условиями применимости загружена не полностью.</p>}
    {examined > 0 ? <p>Проверено CVE {examined} · Применимы {affected} · Требуют уточнения {unknown}</p>
      : ready && <p>В локальной базе NVD нет записей для этого продукта.</p>}
    {items.map(item => <div key={item.cve_id}>
      <Link className="font-mono text-primary hover:underline" to={'/vm/cve?id=' + encodeURIComponent(item.cve_id)}>{item.cve_id}</Link>
      <span className="ml-2">{item.state === 'affected' ? 'Применима' : 'Требует уточнения'}</span>
      <details><summary className="cursor-pointer text-text-secondary">Условия применимости</summary>
        <p>{item.reason}</p><ul className="ml-4 list-disc">{item.evidence.map(line => <li key={line}>{line}</li>)}</ul>
      </details>
    </div>)}
    {affected + unknown > limit && <SoftwarePager label="Страницы результатов NVD" total={affected + unknown}
      pageSize={limit} offset={offset} busy={query.isFetching} onChange={setOffset} />}
  </div>
}
