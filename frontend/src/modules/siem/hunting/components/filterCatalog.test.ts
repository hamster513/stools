import { test } from 'node:test'
import assert from 'node:assert/strict'
import { catalogTree, folderFilters, searchText, type CatalogNode } from './filterCatalog.ts'

const data = {
  folders: [
    { id: 'root', name: 'Threat Hunting', parent: null },
    { id: 'sample', name: 'DEMO_TH_Sample', parent: 'root' },
    { id: 'pentest', name: 'Pentest sample', parent: 'root' },
    { id: 'deep', name: 'Level 2', parent: 'sample' },
  ],
  items: [
    { id: 'dll', name: 'Files for dll sideloading', folder: 'sample' },
    { id: 'iocs', name: 'Demo binary iocs', folder: 'deep' },
    { id: 'priv', name: 'Повышение привилегий', folder: 'pentest' },
  ],
}
function ids(nodes: CatalogNode[]): string[] {
  return nodes.flatMap(n => n.kind === 'folder' ? [n.id, ...ids(n.children)] : [n.id])
}
test('tree preserves hierarchy and filters empty folders only while searching', () => {
  assert.deepEqual(ids(catalogTree(data, '')), ['root', 'sample', 'deep', 'iocs', 'dll', 'pentest', 'priv'])
  assert.deepEqual(ids(catalogTree(data, 'binary')), ['root', 'sample', 'deep', 'iocs'])
})
test('partial/full names, case, Cyrillic, pasted whitespace and invisible separators', () => {
  for (const text of ['DLL', 'Files for dll sideloading', '  Files\u00a0for  dll sideloading\u200b  ']) {
    assert.deepEqual(ids(catalogTree(data, text)), ['root', 'sample', 'dll'])
  }
  assert.deepEqual(ids(catalogTree(data, 'ПРИВИЛЕГ')), ['root', 'pentest', 'priv'])
  assert.equal(searchText('  \u200b '), '')
  assert.deepEqual(catalogTree(data, 'absent'), [])
})
test('matching folder includes descendants; identical names do not merge folders', () => {
  assert.deepEqual(ids(catalogTree(data, 'DEMO_TH')), ['root', 'sample', 'deep', 'iocs', 'dll'])
  const same = { ...data, folders: data.folders.map(f => ({ ...f, name: 'Same' })) }
  assert.deepEqual(ids(catalogTree(same, 'привилег')), ['root', 'pentest', 'priv'])
})
test('older flat API remains searchable during rollout', () => {
  assert.deepEqual(ids(catalogTree({ items: data.items }, 'sideload')), ['dll'])
})

test('folder selection includes every descendant filter, with no duplicates', () => {
  const folders = folderFilters(catalogTree(data, ''))
  assert.deepEqual(folders.get('sample'), ['iocs', 'dll'])
  assert.deepEqual(folders.get('root'), ['iocs', 'dll', 'priv'])
  assert.equal(new Set(folders.get('root')).size, 3)
})
