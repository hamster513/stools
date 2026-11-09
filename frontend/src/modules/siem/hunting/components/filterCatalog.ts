import type { FilterCatalog } from '../api/types'

export type CatalogNode =
  | { kind: 'folder'; id: string; name: string; children: CatalogNode[] }
  | { kind: 'filter'; id: string; name: string }

/** Copying names from SIEM may add non-breaking spaces and invisible separators. */
export function searchText(value: string): string {
  return value.normalize('NFKC').replace(/[\u200B-\u200D\uFEFF]/g, '').replace(/\s+/g, ' ').trim().toLocaleLowerCase()
}

export function catalogTree(catalog: FilterCatalog, search: string): CatalogNode[] {
  const folders = new Map<string, Extract<CatalogNode, { kind: 'folder' }>>()
  const roots: CatalogNode[] = []
  for (const folder of catalog.folders ?? []) folders.set(folder.id, { kind: 'folder', id: folder.id, name: folder.name, children: [] })
  for (const folder of catalog.folders ?? []) {
    const node = folders.get(folder.id)!
    const parent = folder.parent ? folders.get(folder.parent) : undefined
    ;(parent?.children ?? roots).push(node)
  }
  for (const item of catalog.items) {
    const parent = item.folder ? folders.get(item.folder) : undefined
    ;(parent?.children ?? roots).push({ kind: 'filter', id: item.id, name: item.name })
  }
  const needle = searchText(search)
  function prune(nodes: CatalogNode[], parentMatches = false): CatalogNode[] {
    return nodes.flatMap((node): CatalogNode[] => {
      const matches = parentMatches || !needle || searchText(node.name).includes(needle)
      if (node.kind === 'filter') return matches ? [node] : []
      const children = prune(node.children, matches)
      return matches || children.length ? [{ ...node, children }] : []
    }).sort((a, b) => a.kind === b.kind ? a.name.localeCompare(b.name) : a.kind === 'folder' ? -1 : 1)
  }
  return prune(roots)
}

/** Complete descendant IDs for folder selection, independent of the search result. */
export function folderFilters(nodes: CatalogNode[]): Map<string, string[]> {
  const result = new Map<string, string[]>()
  function collect(list: CatalogNode[]): string[] {
    return list.flatMap(node => {
      if (node.kind === 'filter') return [node.id]
      const ids = collect(node.children)
      result.set(node.id, ids)
      return ids
    })
  }
  collect(nodes)
  return result
}
