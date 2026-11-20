import { Fragment, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api, buildQuery, errorText } from '@/api/client'
import { ErrorState } from '@/components/ui/ErrorState'
import { FIELD } from '@/components/ui/Field'
import { Spinner } from '@/components/ui/Spinner'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { SoftwarePager } from './software/SoftwarePager'
import { SbomNvdFindings } from './SbomNvdFindings'

const pageSize = 8
const sourceNames: Record<string, string> = { ksc: 'KSC', maxpatrol: 'MaxPatrol' }

interface ComponentPage {
  total: number
  identified: number
  nvd_identified: number
  items: { ref: string; name: string; version: string | null; sources: string[]; publisher: string | null
    purl: string | null; cpe: string | null; winget_id: string | null }[]
}

export function SbomSoftware({ path, revision, total }: { path: string; revision: string | null; total: number }) {
  const [search, setSearch] = useState('')
  const [expanded, setExpanded] = useState<string | null>(null)
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
      <p className="text-text-secondary">С идентификатором пакета для Trivy {data.identified} · Сопоставлено с продуктом NVD {data.nvd_identified}</p>
      {data.items.length > 0 ? <div className="overflow-x-auto"><table aria-label="Установленные компоненты" className="w-full text-left text-xs">
        <thead className="border-b border-grid text-text-secondary"><tr><th className="py-2">Название ПО</th><th>Установленная версия</th><th>Источник</th><th>Сопоставление</th></tr></thead>
        <tbody>{data.items.map(c => <Fragment key={c.ref}><tr className="border-b border-grid align-top">
          <td className="py-1.5 pr-3 text-text">{c.name}{c.publisher && <div className="text-text-secondary">{c.publisher}</div>}</td>
          <td className="pr-3">{c.version || 'Не указана'}</td><td className="pr-3">{c.sources.map(s => sourceNames[s] ?? s).join(', ')}</td>
          <td>{c.purl && <span title={c.purl}>Trivy · PURL</span>}
            {c.cpe && <button type="button" aria-expanded={expanded === c.ref} className="text-primary hover:underline"
              onClick={() => setExpanded(expanded === c.ref ? null : c.ref)}>Проверить по NVD</button>}
            {c.winget_id && <div className="text-text-secondary">WinGet · {c.winget_id}</div>}
            {!c.purl && !c.cpe && <span className="text-text-secondary">{c.version ? 'Требуется сопоставление' : 'Нужна версия'}</span>}</td>
        </tr>{expanded === c.ref && c.cpe && <tr><td colSpan={4} className="border-b border-grid px-3 py-2">
          <code className="break-all text-text-secondary">{c.cpe}</code>
          <SbomNvdFindings key={path + String(revision) + c.ref} url={path + '/components/' + encodeURIComponent(c.ref) + '/nvd'} revision={revision} />
        </td></tr>}</Fragment>)}</tbody></table></div> : <p className="text-text-secondary">По запросу ничего не найдено.</p>}
      {(data.total > pageSize || offset > 0) && <SoftwarePager label="Страницы состава ПО" offset={offset} total={data.total} pageSize={pageSize}
        busy={list.isFetching} onChange={next => setPage({ query, revision, offset: next })} />}
    </>}
  </section>
}
