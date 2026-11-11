import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ShieldCheck } from 'lucide-react'
import { api, buildQuery, errorText } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FIELD } from '@/components/ui/Field'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { useCan } from '@/lib/can'
import { Link, useRouter, useSearchParams } from '@/lib/router'

interface KscVuln {
  id: number
  software_id: number
  asset_id: number | null
  server_id: number
  snapshot_id: number
  host_id: string
  host_name: string
  name: string
  version: string
  publisher: string
  cve_id: string
  cvss: number | null
  epss: number | null
  kev: boolean
  state: 'affected' | 'unknown'
  reason: string
  evidence: string[]
  collected_at: string
  checked_at: string
}
interface KscVulnsResponse { items: KscVuln[]; total: number; nvd_ready: boolean }
const PAGE_SIZE = 100

export function KscVulns() {
  const { read } = useCan('vm')
  const assets = useCan('assets')
  const params = useSearchParams()
  const { navigate } = useRouter()
  const assetId = params.get('asset_id') && /^\d+$/.test(params.get('asset_id')!) ? Number(params.get('asset_id')) : undefined
  const state = params.get('state') === 'affected' ? 'affected' : params.get('state') === 'unknown' ? 'unknown' : undefined
  const [search, setSearch] = useState(params.get('q') ?? '')
  const q = useDebouncedValue(search, 250)
  const [page, setPage] = useState({ q: '', offset: 0 })
  const offset = page.q === q ? page.offset : 0
  const query = useQuery<KscVulnsResponse>({
    queryKey: ['vm-ksc-vulns', assetId, state, q, offset],
    queryFn: () => api.get(`/api/vm/ksc-vulns${buildQuery({ asset_id: assetId, state, q, limit: PAGE_SIZE, offset })}`),
    enabled: read,
  })
  const setFilter = (value: string) => navigate(`/vm/vulns${buildQuery({ source: 'ksc', asset_id: assetId, state: value, q })}`)
  const error = errorText(query.error, 'Не удалось загрузить уязвимости KSC')
  const data = query.data
  if (!read) return <div className="p-6"><ErrorState message="Нет доступа к модулю VM" /></div>
  return (
    <section aria-label="Уязвимости из инвентаря KSC" className="flex h-full min-h-0 flex-col">
      <header className="flex shrink-0 flex-wrap items-end gap-3 border-b border-grid bg-surface px-4 py-3">
        <h1 className="self-center text-sm font-semibold text-text">Уязвимости · KSC</h1>
        <label className="min-w-48 flex-1 text-xs text-text-secondary">Поиск по хосту, ПО или CVE
          <input type="search" value={search} onChange={(event) => { setSearch(event.target.value); setPage({ q: event.target.value, offset: 0 }) }} className={`${FIELD} mt-1 w-full`} />
        </label>
        <label className="text-xs text-text-secondary">Результат сопоставления
          <select value={state ?? ''} onChange={(event) => setFilter(event.target.value)} className={`${FIELD} mt-1 block`}>
            <option value="">Все результаты</option><option value="affected">Совпала версия</option><option value="unknown">Кандидаты · нужна проверка</option>
          </select>
        </label>
        {assetId !== undefined && <div className="flex items-center gap-2 text-xs text-text">
          {assets.read ? <Link to={`/assets/list?asset=${assetId}`} className="underline">Актив #{assetId}</Link> : <span>Актив #{assetId}</span>}
          <Button aria-label="Снять фильтр по активу" onClick={() => navigate(`/vm/vulns${buildQuery({ source: 'ksc', state, q })}`)}>Снять</Button>
        </div>}
      </header>
      <div className="shrink-0 space-y-1 border-b border-grid px-4 py-2 text-xs text-text-secondary">
        <p>Источник: инвентарь KSC. Совпадение версии не подтверждает возможность эксплуатации; кандидаты требуют проверки условий.</p>
        {data && !data.nvd_ready && <p role="status">Условия применимости NVD загружены не полностью. Обновите справочник NVD.</p>}
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        {query.isLoading && <FullPageSpinner />}
        {error && <div className="p-6"><ErrorState message={error} onRetry={() => query.refetch()} /></div>}
        {!error && data && (data.items.length === 0 ? <div className="p-6"><EmptyState icon={ShieldCheck} title="Совпадений CVE нет" description={data.nvd_ready ? 'В собранном ПО нет результатов по выбранным условиям. Это не гарантирует отсутствие уязвимостей. Проверьте инвентарь в карточке актива.' : 'Условия применимости NVD загружены не полностью. Обновите справочник NVD. Инвентарь ПО доступен в карточке актива.'} /></div> :
          <table className="w-full text-left text-xs">
            <caption className="sr-only">CVE для ПО из последних инвентарей KSC</caption>
            <thead className="sticky top-0 bg-surface text-text-secondary"><tr>
              {['Хост / источник', 'ПО / установленная версия', 'CVE / приоритет', 'Результат и условия'].map((label) => <th key={label} scope="col" className="px-4 py-2 font-medium">{label}</th>)}
            </tr></thead>
            <tbody>{data.items.map((item) => <tr key={item.id} className="border-t border-grid align-top hover:bg-row-hover">
              <td className="max-w-56 break-words px-4 py-3 text-text"><div>{item.host_name || item.host_id}</div><div className="mt-1 text-text-secondary">KSC #{item.server_id}</div>
                {item.asset_id !== null && assets.read && <Link to={`/assets/list?asset=${item.asset_id}`} className="mt-1 inline-block underline">Актив #{item.asset_id}</Link>}
              </td>
              <td className="max-w-72 break-words px-4 py-3 text-text"><div>{item.name || 'Без названия'}</div><div className="mt-1 font-mono">{item.version || 'Версия неизвестна'}</div><div className="mt-1 text-text-secondary">{item.publisher || 'Издатель неизвестен'}</div></td>
              <td className="whitespace-nowrap px-4 py-3 text-text"><a href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(item.cve_id)}`} target="_blank" rel="noreferrer" className="font-mono underline">{item.cve_id}</a>
                <div className="mt-1 text-text-secondary">CVSS: {item.cvss ?? '—'}</div><div className="text-text-secondary">EPSS: {item.epss === null ? '—' : `${(item.epss * 100).toFixed(2)}%`}</div>
                {item.kev && <span className="mt-1 inline-block rounded border border-risk-high px-1 text-risk-high">CISA KEV</span>}
              </td>
              <td className="min-w-64 max-w-lg px-4 py-3 text-text"><span className={item.state === 'affected' ? 'text-risk-high' : 'text-text-secondary'}>{item.state === 'affected' ? 'Совпала версия' : 'Кандидат · нужна проверка'}</span>
                <p className="mt-1 break-words">{item.reason}</p>
                <details className="mt-2 text-text-secondary"><summary className="cursor-pointer">Условия и даты проверки</summary>
                  {item.evidence.length > 0 && <ul className="mt-1 list-inside list-disc space-y-1 break-words">{item.evidence.map((evidence, index) => <li key={index}>{evidence}</li>)}</ul>}
                  <p className="mt-1">Инвентарь: {new Date(item.collected_at).toLocaleString('ru-RU')}</p><p>Проверено: {new Date(item.checked_at).toLocaleString('ru-RU')}</p>
                </details>
              </td>
            </tr>)}</tbody>
          </table>)}
      </div>
      {!error && data && <nav aria-label="Страницы уязвимостей KSC" className="flex shrink-0 items-center justify-between gap-2 border-t border-grid bg-surface px-4 py-2 text-xs">
        <Button disabled={offset === 0} onClick={() => setPage({ q, offset: Math.max(0, offset - PAGE_SIZE) })}>Назад</Button>
        <span aria-live="polite" className="text-text-secondary">{data.total === 0 ? 0 : offset + 1}–{Math.min(offset + data.items.length, data.total)} из {data.total}</span>
        <Button disabled={offset + PAGE_SIZE >= data.total} onClick={() => setPage({ q, offset: offset + PAGE_SIZE })}>Далее</Button>
      </nav>}
    </section>
  )
}
