import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api, buildQuery, errorText } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { Spinner } from '@/components/ui/Spinner'
import { FIELD } from '@/components/ui/Field'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { useCan } from '@/lib/can'
import { Link } from '@/lib/router'
import { inventoryEmptyText, type InventoryStatus } from './softwareState'

interface Software {
  id: number
  server_id: number
  snapshot_id: number
  host_id: string
  host_name: string
  name: string
  version: string
  publisher: string
  product_id: string
  installed_on: string | null
  install_dir: string
  collected_at: string
  assessment: 'matched' | 'no_match' | 'unknown' | 'pending'
  cve_count: number
}
interface SoftwareResponse {
  items: Software[]
  total: number
  inventories: { server_id: number; snapshot_id: number | null; host_id: string; host_name: string; collected_at: string | null; status: InventoryStatus; error: string | null }[]
  nvd_ready: boolean
}
const PAGE_SIZE = 100
const ASSESSMENT = { matched: 'Есть совпадения CVE', no_match: 'Совпадений нет', unknown: 'Требует проверки', pending: 'Ожидает проверки' }

export function SoftwareInventory({ assetId }: { assetId: number }) {
  const { read } = useCan('assets')
  const vm = useCan('vm')
  const [search, setSearch] = useState('')
  const q = useDebouncedValue(search, 250)
  const [page, setPage] = useState({ q: '', offset: 0 })
  const offset = page.q === q ? page.offset : 0
  const query = useQuery<SoftwareResponse>({
    queryKey: ['assets-software', assetId, q, offset],
    queryFn: () => api.get(`/api/assets/assets/${assetId}/software${buildQuery({ q, limit: PAGE_SIZE, offset })}`),
    enabled: read,
  })
  if (!read) return null
  const data = query.data
  const error = errorText(query.error, 'Не удалось загрузить инвентарь ПО')
  return (
    <section aria-label="Установленное ПО KSC" className="mt-4 space-y-2 border-t border-grid pt-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-xs font-semibold text-text">Установленное ПО · KSC{data ? ` (${data.total})` : ''}</h2>
        {vm.read && <Link to={`/vm/vulns?source=ksc&asset_id=${assetId}`} className="text-xs text-text underline">CVE этого актива в VM</Link>}
      </div>
      <label className="block text-text-secondary">
        Поиск ПО
        <input type="search" value={search} onChange={(event) => { setSearch(event.target.value); setPage({ q: event.target.value, offset: 0 }) }} className={`${FIELD} mt-1 w-full`} placeholder="Название, версия, издатель" />
      </label>
      {query.isLoading && <div role="status" className="flex items-center gap-2 py-3"><Spinner /> Загрузка инвентаря…</div>}
      {error && <div role="alert" className="space-y-2 text-kind-1"><p>{error}</p><Button onClick={() => query.refetch()}>Повторить</Button></div>}
      {!error && data && <>
        <div className="space-y-1 text-text-secondary">
          {data.inventories.map((inventory) => <p key={`${inventory.server_id}:${inventory.host_id}`}>
            KSC #{inventory.server_id} · {inventory.host_name || inventory.host_id} · {inventory.status === 'complete' ? 'Собран' : inventory.status === 'error' ? 'Ошибка сбора' : 'Не собран'}
            {inventory.collected_at && ` · ${new Date(inventory.collected_at).toLocaleString('ru-RU')}`}
            {inventory.error && <span className="text-kind-1"> · {inventory.error}</span>}
          </p>)}
          {!data.nvd_ready && <p>Условия применимости NVD загружены не полностью. Обновите справочник NVD.</p>}
        </div>
        {data.items.length === 0 ? <p role="status" className="py-3 text-text-secondary">{inventoryEmptyText(data.inventories.map((inventory) => inventory.status), Boolean(q))}</p> : <>
          <div className="overflow-x-auto rounded border border-grid">
            <table className="w-full text-left text-xs">
              <caption className="sr-only">ПО из последних инвентарей KSC</caption>
              <thead className="bg-app-bg text-text-secondary"><tr><th scope="col" className="px-2 py-2">ПО / версия</th><th scope="col" className="px-2 py-2">Издатель</th><th scope="col" className="px-2 py-2">Оценка CVE</th></tr></thead>
              <tbody>{data.items.map((software) => <tr key={software.id} className="border-t border-grid align-top">
                <td className="max-w-64 break-words px-2 py-2 text-text"><div className="font-medium">{software.name || 'Без названия'}</div><div className="font-mono">{software.version || 'Версия неизвестна'}</div>
                  <details className="mt-1 text-text-secondary"><summary className="cursor-pointer">Данные KSC</summary><div className="mt-1 space-y-1">
                    <p>KSC #{software.server_id} · {software.host_name || software.host_id}</p>
                    <p>Собрано: {new Date(software.collected_at).toLocaleString('ru-RU')}</p>
                    <p>Установлено: {software.installed_on || 'неизвестно'}</p>
                    {software.product_id && <p>Идентификатор: {software.product_id}</p>}
                    {software.install_dir && <p className="break-all">Путь: {software.install_dir}</p>}
                  </div></details>
                </td>
                <td className="max-w-40 break-words px-2 py-2 text-text-secondary">{software.publisher || '—'}</td>
                <td className="px-2 py-2 text-text"><span>{ASSESSMENT[software.assessment]}</span>{software.cve_count > 0 && <div className="mt-1">CVE: {software.cve_count}</div>}</td>
              </tr>)}</tbody>
            </table>
          </div>
        </>}
        {(data.total > PAGE_SIZE || offset > 0) && <nav aria-label="Страницы инвентаря ПО" className="flex items-center justify-between gap-2">
          <Button disabled={offset === 0} onClick={() => setPage({ q, offset: Math.max(0, offset - PAGE_SIZE) })}>Назад</Button>
          <span className="text-text-secondary">{data.total === 0 ? 0 : offset + 1}–{Math.min(offset + data.items.length, data.total)} из {data.total}</span>
          <Button disabled={offset + PAGE_SIZE >= data.total} onClick={() => setPage({ q, offset: offset + PAGE_SIZE })}>Далее</Button>
        </nav>}
        <p className="text-text-secondary">Отсутствие совпадений CVE не гарантирует отсутствие уязвимостей.</p>
      </>}
    </section>
  )
}
