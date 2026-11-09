import { useState } from 'react'
import { ChevronDown, ChevronRight, Folder, FolderOpen, Search } from 'lucide-react'
import { api } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { FIELD } from '@/components/ui/Field'
import { useFilterCatalog } from '../api/queries'
import type { CatalogQuery } from '../api/types'
import { apiMessage } from '../format'
import { catalogTree, folderFilters, searchText, type CatalogNode } from './filterCatalog'

export function FilterCatalogPicker({ existing, onAdd }: { existing: string[]; onAdd: (queries: CatalogQuery[]) => void }) {
  const [open, setOpen] = useState(false)
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<string[]>([])
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set())
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const catalog = useFilterCatalog(open)
  const tree = catalogTree(catalog.data ?? { items: [] }, search)
  const searching = Boolean(searchText(search))
  const byFolder = folderFilters(catalogTree(catalog.data ?? { items: [] }, ''))
  const selectedIds = selected.filter(id => !existing.includes(id))
  async function add() {
    setLoading(true); setError(null)
    try {
      const queries: CatalogQuery[] = []
      // Limit requests when importing a large folder; apply only after every query is read.
      for (let offset = 0; offset < selectedIds.length; offset += 4) {
        queries.push(...await Promise.all(selectedIds.slice(offset, offset + 4).map(id =>
          api.get<CatalogQuery>(`/api/siem/hunting/filters/catalog/${encodeURIComponent(id)}`))))
      }
      onAdd(queries); setSelected([]); setOpen(false)
    } catch (exc) { setError(apiMessage(exc, 'Не удалось прочитать выбранные фильтры SIEM')) }
    finally { setLoading(false) }
  }
  function renderNodes(nodes: CatalogNode[]) {
    return nodes.map(node => {
      if (node.kind === 'filter') return <li key={`filter:${node.id}`}>
        <label className="flex min-w-0 cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-xs text-text hover:bg-row-hover">
          <input type="checkbox" aria-label={node.name} checked={selected.includes(node.id) || existing.includes(node.id)} disabled={existing.includes(node.id) || loading}
            onChange={e => setSelected(ids => e.target.checked ? [...ids, node.id] : ids.filter(id => id !== node.id))} />
          <Search size={13} className="shrink-0 text-text-secondary" aria-hidden />
          <span className="min-w-0 truncate" title={node.name}>{node.name}</span>
          {existing.includes(node.id) && <span className="shrink-0 text-text-secondary">уже в ханте</span>}
        </label>
      </li>
      const ids = byFolder.get(node.id) ?? []
      const selectable = ids.filter(id => !existing.includes(id))
      const checkedCount = ids.filter(id => selected.includes(id) || existing.includes(id)).length
      const expanded = searching || !collapsed.has(node.id)
      const Chevron = expanded ? ChevronDown : ChevronRight
      const Icon = expanded ? FolderOpen : Folder
      return <li key={`folder:${node.id}`}>
        <div className="flex items-center gap-1 pl-2">
          <input type="checkbox" aria-label={`Выбрать папку ${node.name}`}
            title="Все фильтры папки и подпапок, включая скрытые поиском"
            checked={ids.length > 0 && checkedCount === ids.length}
            ref={input => { if (input) input.indeterminate = checkedCount > 0 && checkedCount < ids.length }}
            disabled={!selectable.length || loading || catalog.isFetching}
            onChange={e => setSelected(current => e.target.checked
              ? [...new Set([...current, ...selectable])]
              : current.filter(id => !selectable.includes(id)))} />
        <button type="button" aria-expanded={expanded} aria-label={node.name}
          disabled={searching}
          onClick={() => setCollapsed(current => {
            const next = new Set(current)
            if (next.has(node.id)) next.delete(node.id); else next.add(node.id)
            return next
          })}
          className="flex w-full min-w-0 items-center gap-2 rounded px-2 py-1.5 text-left text-xs text-text hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">
          <Chevron size={13} className="shrink-0" aria-hidden />
          <Icon size={15} className="shrink-0 text-text-secondary" aria-hidden />
          <span className="min-w-0 truncate" title={node.name}>{node.name}</span>
          <span className="ml-auto shrink-0 text-text-secondary">{ids.length}</span>
        </button>
        </div>
        {expanded && <ul className="ml-4 border-l border-grid pl-2">{renderNodes(node.children)}</ul>}
      </li>
    })
  }
  return <div className="mb-3">
    <Button type="button" disabled={loading} onClick={() => setOpen(!open)}>Добавить из SIEM</Button>
    {open && <div className="mt-2 grid gap-2 rounded border border-grid bg-surface p-3">
      <p className="text-xs text-text-secondary">Выберите фильтры из папки, указанной в настройках Threat Hunting, и всех её вложенных папок. Флажок папки выбирает все фильтры в ней и подпапках, включая скрытые поиском. Каждый фильтр станет отдельным запросом ханта.</p>
      <div className="flex gap-2">
        <input className={FIELD} aria-label="Поиск фильтров SIEM" type="search" placeholder="Поиск фильтров и папок" value={search} onChange={e => setSearch(e.target.value)} />
        <Button type="button" loading={catalog.isFetching} onClick={() => catalog.refetch()}>Обновить список</Button>
      </div>
      {catalog.isFetching && <p role="status" className="text-xs text-text-secondary">Загружаем папки и фильтры SIEM…</p>}
      {catalog.isError && <p role="alert" className="text-xs text-kind-1">{apiMessage(catalog.error, 'Не удалось загрузить каталог SIEM')}</p>}
      {!catalog.isFetching && !catalog.isError && tree.length === 0 && <p className="text-xs text-text-secondary">{searching ? 'По этому запросу ничего не найдено.' : 'Фильтры не найдены в выбранной папке и её вложенных папках.'}</p>}
      <div className="max-h-80 overflow-auto rounded border border-grid p-1">
        <ul aria-label="Папки и фильтры SIEM">{renderNodes(tree)}</ul>
      </div>
      {error && <p role="alert" className="text-xs text-kind-1">{error}</p>}
      <div><Button type="button" loading={loading} disabled={!selectedIds.length || catalog.isError || catalog.isFetching} onClick={() => void add()}>Добавить выбранные ({selectedIds.length})</Button></div>
    </div>}
  </div>
}
