import { useState } from 'react'
import { api } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { FIELD } from '@/components/ui/Field'
import { useFilterCatalog } from '../api/queries'
import type { CatalogQuery } from '../api/types'
import { apiMessage } from '../format'

export function FilterCatalogPicker({ existing, onAdd }: { existing: string[]; onAdd: (queries: CatalogQuery[]) => void }) {
  const [open, setOpen] = useState(false)
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const catalog = useFilterCatalog(open)
  const items = (catalog.data?.items ?? []).filter(item => item.name.toLowerCase().includes(search.toLowerCase()))
  async function add() {
    setLoading(true); setError(null)
    try {
      const queries = await Promise.all(selected.filter(id => !existing.includes(id)).map(id =>
        api.get<CatalogQuery>(`/api/siem/hunting/filters/catalog/${encodeURIComponent(id)}`)))
      onAdd(queries); setSelected([]); setOpen(false)
    } catch (exc) { setError(apiMessage(exc, 'Не удалось прочитать выбранные фильтры SIEM')) }
    finally { setLoading(false) }
  }
  return <div className="mb-3">
    <Button type="button" onClick={() => setOpen(!open)}>Добавить из SIEM</Button>
    {open && <div className="mt-2 grid gap-2 rounded border border-grid bg-surface p-3">
      <p className="text-xs text-text-secondary">Выберите фильтры из папки, указанной в настройках Threat Hunting. Каждый станет отдельным запросом ханта.</p>
      <div className="flex gap-2">
        <input className={FIELD} aria-label="Поиск фильтров SIEM" placeholder="Поиск по Name" value={search} onChange={e => setSearch(e.target.value)} />
        <Button type="button" loading={catalog.isFetching} onClick={() => catalog.refetch()}>Обновить список</Button>
      </div>
      {catalog.isError && <p role="alert" className="text-xs text-kind-1">{apiMessage(catalog.error, 'Не удалось загрузить каталог SIEM')}</p>}
      {!catalog.isFetching && !catalog.isError && items.length === 0 && <p className="text-xs text-text-secondary">Фильтры не найдены в выбранной папке.</p>}
      <div className="max-h-72 overflow-auto">
        {items.map(item => <label key={item.id} className="flex items-center gap-2 border-b border-grid py-2 text-xs text-text">
          <input type="checkbox" checked={selected.includes(item.id) || existing.includes(item.id)} disabled={existing.includes(item.id) || loading}
            onChange={e => setSelected(ids => e.target.checked ? [...ids, item.id] : ids.filter(id => id !== item.id))} />
          <span>{item.name}</span>{existing.includes(item.id) && <span className="text-text-secondary">уже в ханте</span>}
        </label>)}
      </div>
      {error && <p role="alert" className="text-xs text-kind-1">{error}</p>}
      <div><Button type="button" loading={loading} disabled={!selected.length || catalog.isError} onClick={() => void add()}>Добавить выбранные ({selected.length})</Button></div>
    </div>}
  </div>
}
