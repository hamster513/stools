import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api, buildQuery, errorText } from '@/api/client'
import { ErrorState } from '@/components/ui/ErrorState'
import { Spinner } from '@/components/ui/Spinner'
import { Link } from '@/lib/router'
import { SoftwarePager } from './software/SoftwarePager'

const pageSize = 20

export function UnlinkedVmFindings({ path, total, version }: { path: string; total: number; version: string }) {
  const [open, setOpen] = useState(false)
  const [page, setPage] = useState({ version, offset: 0 })
  const offset = page.version === version && page.offset < total ? page.offset : 0
  const list = useQuery<{ total: number; items: { id: string }[] }>({
    queryKey: ['sbom-unlinked', path, version, offset],
    queryFn: ({ signal }) => api.get(path + '/comparison' + buildQuery({ group: 'unlinked', limit: pageSize, offset }), { signal }),
    enabled: open, staleTime: 60000,
  })
  return <section className="border-t border-grid pt-3">
    <button type="button" aria-expanded={open} onClick={() => setOpen(!open)} className="text-left font-medium text-primary hover:underline">
      {open ? 'Скрыть' : 'Показать'} CVE MaxPatrol без привязки к ПО ({total.toLocaleString('ru-RU')})
    </button>
    {open && <div className="mt-2 space-y-2">
      <p className="text-text-secondary">MaxPatrol сообщил эти CVE для хоста. В его находках не указаны пакет и исправленная версия.</p>
      {list.isPending && <Spinner />}
      {list.isError && <ErrorState message={errorText(list.error, 'Не удалось получить находки MaxPatrol') ?? ''} onRetry={() => list.refetch()} />}
      {list.data && <>
        <ul aria-label="CVE MaxPatrol без привязки к ПО" className="grid gap-1 sm:grid-cols-2">
          {list.data.items.map(item => <li key={item.id}>
            <Link to={'/vm/cve?id=' + encodeURIComponent(item.id)} className="font-mono text-primary hover:underline">{item.id}</Link>
          </li>)}
        </ul>
        {(list.data.total > pageSize || offset > 0) && <SoftwarePager label="Страницы CVE MaxPatrol" offset={offset} total={list.data.total}
          pageSize={pageSize} busy={list.isFetching} onChange={next => setPage({ version, offset: next })} />}
      </>}
    </div>}
  </section>
}
