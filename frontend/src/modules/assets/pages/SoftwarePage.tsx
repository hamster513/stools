import { useState } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { Package } from 'lucide-react'
import { api, buildQuery, errorText } from '@/api/client'
import { ErrorState } from '@/components/ui/ErrorState'
import { EmptyState } from '@/components/ui/EmptyState'
import { Spinner } from '@/components/ui/Spinner'
import { FIELD } from '@/components/ui/Field'
import { useCan } from '@/lib/can'
import { useRouter, useSearchParams } from '@/lib/router'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { PAGE_SIZE, SoftwarePager } from './software/SoftwarePager'
import { SoftwareProductDrawer } from './software/SoftwareProductDrawer'

interface Product { vendor_key: string; product_key: string; name: string; publisher: string; version_count: number; host_count: number }
export function SoftwarePage() {
  const { read } = useCan('assets')
  const params = useSearchParams(), { navigate } = useRouter()
  const [search, setSearch] = useState(params.get('q') ?? '')
  const q = useDebouncedValue(search, 250)
  const [page, setPage] = useState({ q: '', offset: 0 })
  const offset = page.q === q ? page.offset : 0
  const product = params.get('product'), vendor = params.get('vendor') ?? ''
  const query = useQuery<{ items: Product[]; total: number; inventory_count: number }>({
    queryKey: ['assets-software-products', q, offset],
    queryFn: () => api.get(`/api/assets/software/products${buildQuery({ q, limit: PAGE_SIZE, offset })}`),
    enabled: read, placeholderData: keepPreviousData,
  })
  if (!read) return <div className="p-6"><ErrorState message="Нет доступа к Assets" /></div>
  const data = query.data
  return <section aria-label="Каталог ПО" className="flex h-full min-h-0 flex-col">
    <header className="flex shrink-0 flex-wrap items-end gap-3 border-b border-grid bg-surface px-4 py-3">
      <h1 className="self-center text-sm font-semibold text-text">ПО</h1>
      <label className="min-w-48 flex-1 text-xs text-text-secondary">Поиск по названию, издателю или версии
        <input type="search" maxLength={255} value={search} onChange={(e) => { setSearch(e.target.value); setPage({ q: e.target.value, offset: 0 }) }} className={`${FIELD} mt-1 w-full`} />
      </label>
    </header>
    <p className="border-b border-grid px-4 py-2 text-xs text-text-secondary">ПО из последних инвентарей KSC. Продукты объединены по нормализованным названию и издателю; версии сгруппированы внутри. Нажмите продукт, чтобы увидеть версии и хосты.</p>
    <div className="min-h-0 flex-1 overflow-auto p-4">
      {query.isError ? <ErrorState message={errorText(query.error, 'Не удалось загрузить ПО') ?? 'Не удалось загрузить ПО'} onRetry={() => query.refetch()} /> : !data ? <Spinner /> : <>
        {query.isFetching && <p role="status" className="text-xs text-text-secondary">Обновление…</p>}
        {data.total === 0 ? <EmptyState icon={Package} title={q ? 'ПО не найдено' : 'Инвентарь ПО пуст'} description={q ? 'Измените поисковый запрос.' : data.inventory_count ? 'В последних полных инвентарях KSC нет установленного ПО. Это не подтверждает отсутствие ПО на хостах.' : 'Нужен сбор или импорт KSC с инвентаризацией ПО. Старые или ошибочные инвентари не считаются текущими установками.'} /> :
          <div className="overflow-x-auto"><table className="w-full text-left text-xs">
            <caption className="sr-only">Продукты, версии и количество хостов</caption>
            <thead className="text-text-secondary"><tr>{['Продукт', 'Издатель', 'Версий', 'Хостов'].map((label) => <th key={label} scope="col" className="p-3 font-medium">{label}</th>)}</tr></thead>
            <tbody>{data.items.map((item) => <tr key={JSON.stringify([item.vendor_key, item.product_key])} className="border-t border-grid align-top hover:bg-row-hover">
              <td className="p-3"><button className="break-words text-left font-medium text-text underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" onClick={() => navigate(`/assets/software${buildQuery({ q, vendor: item.vendor_key, product: item.product_key })}`)}>{item.name}</button></td>
              <td className="break-words p-3 text-text-secondary">{item.publisher || 'Не указан'}</td><td className="p-3 font-mono text-text">{item.version_count}</td><td className="p-3 font-mono text-text">{item.host_count}</td>
            </tr>)}</tbody>
          </table></div>}
        <SoftwarePager label="Страницы продуктов" offset={offset} total={data.total} busy={query.isFetching} onChange={(value) => setPage({ q, offset: value })} />
      </>}
    </div>
    {product && <SoftwareProductDrawer key={JSON.stringify([vendor, product])} vendorKey={vendor} productKey={product} onClose={() => navigate(`/assets/software${buildQuery({ q })}`)} />}
  </section>
}
