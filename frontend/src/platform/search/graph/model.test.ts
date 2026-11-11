import assert from 'node:assert/strict'
import { test } from 'node:test'
import type { Dossier, Entity, Row, Section } from '../api.ts'
import { buildGraph, filterGraph, connections, layoutGraph, PAGE_SIZE, MAX_NODES, MAX_EDGES } from './model.ts'
const entity = (id: string, title = id): Entity => ({ id, title, kind: id.split(':')[0] as Entity['kind'], domain: '', href: '/assets', facts: [] })
const row = (e: Entity, reason = 'Прямое членство', source = 'AD'): Row => ({ id: e.id, title: e.title, target: e, reason, source, href: '/assets', observed_at: '2026-11-11T10:00:00Z', date_label: 'Снимок', facts: [] })
const section = (id: string, rows: Row[], has_more = false): Section => ({ id, title: id, note: 'Сохранённый снимок', items: rows, has_more })
const dossier = (e: Entity, sections: Section[]): Dossier => ({ entity: e, sections, notes: [] })
const user = entity('user:1', 'Alice'), group = entity('group:1', 'Users'), host = entity('host:1', 'PC1')

test('both sides of membership are one directed edge with both explanations', () => {
  const a = dossier(user, [section('groups', [row(group)])])
  const b = dossier(group, [section('members', [row(user, 'Пользователь')])])
  const graph = buildGraph(user.id, { [user.id]: a, [group.id]: b }, { [user.id]: 12, [group.id]: 12 })
  assert.equal(graph.nodes.length, 2); assert.equal(graph.edges.length, 1)
  assert.equal(graph.edges[0].from, user.id); assert.equal(graph.edges[0].to, group.id)
  assert.equal(graph.edges[0].evidence.length, 2)
})
test('user/host reverse views merge without claiming every link is a session', () => {
  const a = dossier(user, [section('hosts', [row(host, 'Владелец устройства', 'KSC')])])
  const b = dossier(host, [section('users', [row(user, 'Владелец устройства', 'KSC')])])
  const graph = buildGraph(user.id, { [user.id]: a, [host.id]: b }, { [user.id]: 12, [host.id]: 12 })
  assert.equal(graph.edges.length, 1); assert.equal(graph.edges[0].label, 'Связь с хостом')
  assert.equal(graph.edges[0].from, user.id)
})
test('same names stay separate and observation rows are not relationship nodes', () => {
  const a = dossier(user, [section('groups', [row(group), row(entity('group:2', group.title))]), section('observations', [row(host)])])
  const graph = buildGraph(user.id, { [user.id]: a }, { [user.id]: 12 })
  assert.equal(graph.nodes.length, 3); assert(!graph.nodes.some(n => n.id === host.id))
})
test('unresolved policy evidence is not merged by display title across objects', () => {
  const leaf = { ...row(group, 'Область GPO'), id: 'policy:1', target: null }
  const a = dossier(user, [section('hosts', [row(host)]), section('ad_policies', [leaf])])
  const b = dossier(host, [section('ad_policies', [leaf])])
  const graph = buildGraph(user.id, { [user.id]: a, [host.id]: b }, { [user.id]: 12, [host.id]: 12 })
  assert.equal(graph.nodes.filter(n => n.kind === 'policy').length, 2)
})
test('related-host CVEs retain their context rather than infecting the user', () => {
  const a = dossier(user, [section('vulnerabilities', [{ ...row(host, 'PC1', 'VM'), target: null, title: 'CVE-2026-1111' }])])
  const graph = buildGraph(user.id, { [user.id]: a }, { [user.id]: 12 })
  assert.equal(graph.edges[0].label, 'CVE связанного хоста')
  assert.equal(graph.edges[0].evidence[0].reason, 'PC1')
})
test('collapse discards only disconnected descendants, shared nodes survive', () => {
  const a = dossier(user, [section('groups', [row(group)]), section('hosts', [row(host)])])
  const b = dossier(group, [section('members', [row(host), row(entity('host:2'))])])
  const graph = buildGraph(user.id, { [user.id]: a, [group.id]: b }, { [user.id]: 12, [group.id]: 0 })
  assert(graph.nodes.some(n => n.id === host.id)); assert(!graph.nodes.some(n => n.id === 'host:2'))
})
test('paging balances sections and node limit is explicit and never dangles edges', () => {
  const a = dossier(user, [section('groups', Array.from({length: 150}, (_, i) => row(entity(`group:${i}`))), true), section('hosts', [row(host)])])
  const graph = buildGraph(user.id, { [user.id]: a }, { [user.id]: PAGE_SIZE })
  assert.equal(graph.edges.length, PAGE_SIZE); assert(graph.nodes.some(n => n.id === host.id))
  const all = buildGraph(user.id, { [user.id]: a }, { [user.id]: 1000 })
  assert(all.nodes.length <= MAX_NODES); assert(all.limited); assert(all.sourceTruncated.includes(user.id))
  assert(all.edges.every(e => all.nodes.some(n => n.id === e.from) && all.nodes.some(n => n.id === e.to)))
})
test('source/type filtering preserves root and does not show disconnected islands', () => {
  const a = dossier(user, [section('groups', [row(group)]), section('hosts', [row(host, 'Сеанс', 'KSC')])])
  const graph = buildGraph(user.id, { [user.id]: a }, { [user.id]: 12 })
  const filtered = filterGraph(graph, new Set(['host', 'user', 'group']), new Set(['KSC']))
  assert.deepEqual(new Set(filtered.nodes.map(n => n.id)), new Set([user.id, host.id]))
  assert.equal(filterGraph(graph, new Set(), new Set()).nodes.length, 1)
})
test('cycles terminate and layout has distinct finite positions', () => {
  const a = dossier(group, [section('groups', [row(entity('group:2'))])])
  const b = dossier(entity('group:2'), [section('groups', [row(group)])])
  const graph = buildGraph(group.id, { [group.id]: a, 'group:2': b }, { [group.id]: 12, 'group:2': 12 })
  const positions = layoutGraph(graph)
  assert.equal(graph.nodes.length, 2); assert.equal(new Set(Object.values(positions).map(p => `${p.x}:${p.y}`)).size, 2)
  assert(Object.values(positions).every(p => Number.isFinite(p.x) && Number.isFinite(p.y)))
  assert.equal(connections(a).length, 1)
})


test('KSC host membership merges with group members, user context stays indirect', () => {
  const management = { ...group, id: 'kscgroup:1:12' }
  const a = dossier(host, [section('antivirus', [row(management, 'Хост: PC1', 'KSC')])])
  const b = dossier(management, [section('members', [row(host, 'В группе управления KSC', 'KSC')])])
  const graph = buildGraph(host.id, { [host.id]: a, [management.id]: b }, { [host.id]: 12, [management.id]: 12 })
  assert.equal(graph.edges.length, 1); assert.equal(graph.edges[0].label, 'Группа KSC')
  const c = dossier(user, [section('antivirus', [row(management, 'Хост: PC1', 'KSC')])])
  assert.equal(connections(c)[0].edge.label, 'KSC связанного хоста')
  assert.notEqual(connections(c)[0].edge.kind, 'membership')
})

test('dense cyclic membership cannot flood the canvas with edges', () => {
  const groups = Array.from({ length: 30 }, (_, i) => entity(`group:${i}`))
  const cache = Object.fromEntries(groups.map(g => [g.id, dossier(g, [section('groups', groups.filter(other => other.id !== g.id).map(other => row(other)))])]))
  const graph = buildGraph(groups[0].id, cache, Object.fromEntries(groups.map(g => [g.id, 100])))
  assert(graph.limited); assert.equal(graph.edges.length, MAX_EDGES)
  assert(graph.edges.every(e => graph.nodes.some(n => n.id === e.from) && graph.nodes.some(n => n.id === e.to)))
})
