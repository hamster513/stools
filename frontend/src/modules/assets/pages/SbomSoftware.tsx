import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api, buildQuery, errorText } from '@/api/client'
import { ErrorState } from '@/components/ui/ErrorState'
import { FIELD } from '@/components/ui/Field'
import { Spinner } from '@/components/ui/Spinner'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { SoftwarePager } from './software/SoftwarePager'

const pageSize = 8
const sourceNames: Record<string, string> = { ksc: 'KSC', maxpatrol: 'MaxPatrol' }

interface ComponentPage {
  total: number
  identified: number
  items: { ref: string; name: string; version: string | null; sources: string[] }[]
}

export function SbomSoftware({ path, revision, total }: { path: string; revision: string | null; total: number }) {
  const [search, setSearch] = useState('')
  const query = useDebouncedValue(search.trim(), 250)
  const [page, setPage] = useState({ query, revision, offset: 0 })
  const offset = page.query === query && page.revision === revision ? page.offset : 0
  const list = useQuery<ComponentPage>({
    queryKey: ['sbom-components', path, revision, query, offset],
    queryFn: ({ signal }) => api.get(path + '/components' + buildQuery({ q: query, limit: pageSize, offset }), { signal }),
    staleTime: 60000,
  })
  const data = list.data
  return <section aria-label="Установленное ПО в SBOM" className="space-y-2">
    <h3 className="font-medium text-text">Установленное ПО в SBOM ({total.toLocaleString('ru-RU')})</h3>
    <input type="search" aria-label="Поиск ПО по названию или версии" placeholder="Название ПО или версия" maxLength={255}
      value={search} onChange={e => { setSearch(e.target.value); setPage({ query: e.target.value.trim(), revision, offset: 0 }) }} className={FIELD + ' w-full'} />
    {list.isPending && <Spinner />}
    {list.isError && <ErrorState message={errorText(list.error, 'Не удалось получить состав SBOM') ?? ''} onRetry={() => list.refetch()} />}
    {data && <>
      {data.identified === 0 && total > 0 && <p className="text-risk-medium">У компонентов не указан идентификатор пакета (PURL). Для сопоставления с уязвимостями нужен тип пакета, например RPM, DEB или npm.</p>}
      {data.items.length > 0 ? <div className="overflow-x-auto"><table aria-label="Установленные компоненты" className="w-full text-left text-xs">
        <thead className="border-b border-grid text-text-secondary"><tr><th className="py-2">Название ПО</th><th>Установленная версия</th><th>Источник</th></tr></thead>
        <tbody>{data.items.map(c => <tr key={c.ref} className="border-b border-grid align-top">
          <td className="py-1.5 pr-3 text-text">{c.name}</td><td className="pr-3">{c.version || 'Не указана'}</td>
          <td>{c.sources.map(s => sourceNames[s] ?? s).join(', ')}</td>
        </tr>)}</tbody></table></div> : <p className="text-text-secondary">По запросу ничего не найдено.</p>}
      {(data.total > pageSize || offset > 0) && <SoftwarePager label="Страницы состава ПО" offset={offset} total={data.total} pageSize={pageSize}
        busy={list.isFetching} onChange={next => setPage({ query, revision, offset: next })} />}
    </>}
  </section>
}
