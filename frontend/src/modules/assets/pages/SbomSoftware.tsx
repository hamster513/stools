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
const sources = (values: string[]) => [...new Set(values)].map(s => sourceNames[s] ?? s).join(', ')

interface Variant {
  ref: string; version: string | null; sources: string[]; publisher: string | null
  purl: string | null; cpe: string | null; winget_id: string | null; reason: string | null
  arch: string | null; group: string | null; package_type: string | null
  reported_versions: { source: string; version: string }[]
}
interface ComponentPage {
  total: number
  total_names: number
  identified: number
  nvd_identified: number
  coverage_note: string | null
  candidate_profile?: string | null
  items: { name: string; variants: Variant[] }[]
}

export function SbomSoftware({ path, revision }: { path: string; revision: string | null }) {
  const [search, setSearch] = useState('')
  const [openGroup, setOpenGroup] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<string | null>(null)
  const query = useDebouncedValue(search.trim(), 250)
  const [page, setPage] = useState({ query, revision, offset: 0 })
  const offset = page.query === query && page.revision === revision ? page.offset : 0
  const list = useQuery<ComponentPage>({
    queryKey: ['sbom-components', 'by-name', path, revision, query, offset],
    queryFn: ({ signal }) => api.get(path + '/components' + buildQuery({ by_name: true, q: query, limit: pageSize, offset }), { signal }),
    staleTime: 60000,
  })
  const data = list.data
  return <section aria-label="Установленное ПО в SBOM" className="space-y-2">
    <h3 className="font-medium text-text">Установленное ПО в SBOM{data && ` · названий: ${data.total_names.toLocaleString('ru-RU')}`}</h3>
    <input type="search" aria-label="Поиск ПО по названию или версии" placeholder="Название ПО или версия" maxLength={255}
      value={search} onChange={e => { setSearch(e.target.value); setPage({ query: e.target.value.trim(), revision, offset: 0 }) }} className={FIELD + ' w-full'} />
    {list.isPending && <Spinner />}
    {list.isError && <ErrorState message={errorText(list.error, 'Не удалось получить состав SBOM') ?? ''} onRetry={() => list.refetch()} />}
    {data && <>
      {data.coverage_note && <p className="text-risk-medium">{data.coverage_note}</p>}
      <p className="text-text-secondary">Компонентов с PURL {data.identified} · Сопоставлено с продуктом NVD {data.nvd_identified}</p>
      {data.items.length > 0 ? <div className="overflow-x-auto"><table aria-label="Установленные компоненты" className="w-full text-left text-xs">
        <thead className="border-b border-grid text-text-secondary"><tr><th className="py-2">Название ПО</th><th>Установленная версия</th><th>Источник</th><th>Сопоставление</th></tr></thead>
        {data.items.map(({ name, variants }) => {
          const multiple = variants.length > 1
          const open = openGroup === name
          return <tbody key={name}>
            {multiple && <tr className="border-b border-grid align-top">
              <th scope="row" className="py-1.5 pr-3 font-medium">{name}</th>
              <td><button type="button" aria-expanded={open} onClick={() => setOpenGroup(open ? null : name)}
                className="text-primary hover:underline">{open ? 'Скрыть варианты' : 'Показать варианты'} ({variants.length})</button></td>
              <td>{sources(variants.flatMap(v => v.sources))}</td><td />
            </tr>}
            {(!multiple || open) && variants.map(c => <Fragment key={c.ref}>
              <tr className="border-b border-grid align-top">
                <td className="py-1.5 pr-3 text-text">{!multiple && name}
                  {c.publisher && <div className="text-text-secondary">{c.publisher}</div>}</td>
                <td className="pr-3">{c.version || 'Не указана'} {c.arch && <span className="text-text-secondary">{c.arch}</span>}
                  {c.reported_versions.map(v => <div key={v.source + ':' + v.version} className="text-text-secondary">
                    {sourceNames[v.source] ?? v.source} · {v.version}</div>)}
                  {multiple && c.package_type && c.package_type !== 'generic' &&
                    <div className="text-text-secondary">{[c.package_type, c.group].filter(Boolean).join(' · ')}</div>}</td>
                <td className="pr-3">{sources(c.sources)}</td>
                <td>
                  {c.purl && <span title={c.purl}>{c.reason === 'unsupported-distribution'
                    ? (data.candidate_profile ? `PURL · профиль ${data.candidate_profile}` : 'PURL · ОС вне покрытия Trivy')
                    : 'Trivy · PURL'}</span>}
                  {c.cpe && <button type="button" aria-expanded={expanded === c.ref} className="text-primary hover:underline"
                    onClick={() => setExpanded(expanded === c.ref ? null : c.ref)}>Проверить по NVD</button>}
                  {c.winget_id && <div className="text-text-secondary">WinGet · {c.winget_id}</div>}
                  {!c.purl && !c.cpe && <span className="text-text-secondary">{!c.version ? 'Нужна версия'
                    : c.reason === 'missing-or-incompatible-distribution' ? 'Не определён дистрибутив'
                    : 'Нет подтверждённого идентификатора'}</span>}
                </td>
              </tr>
              {expanded === c.ref && c.cpe && <tr><td colSpan={4} className="border-b border-grid px-3 py-2">
                <code className="break-all text-text-secondary">{c.cpe}</code>
                <SbomNvdFindings key={path + String(revision) + c.ref} url={path + '/components/' + encodeURIComponent(c.ref) + '/nvd'} revision={revision} />
              </td></tr>}
            </Fragment>)}
          </tbody>
        })}
      </table></div> : <p className="text-text-secondary">По запросу ничего не найдено.</p>}
      {(data.total > pageSize || offset > 0) && <SoftwarePager label="Страницы состава ПО" offset={offset} total={data.total} pageSize={pageSize}
        busy={list.isFetching} onChange={next => setPage({ query, revision, offset: next })} />}
    </>}
  </section>
}
