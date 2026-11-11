import assert from 'node:assert/strict'
import { test } from 'node:test'
import type { Dossier, Entity, Row, Section } from '../api.ts'
import { buildGraph, categoryId, connections, expandNode, filterGraph, hideNode, initialState, layoutGraph, MAX_NODES, revealHit, searchGraph } from './model.ts'
const entity = (id: string, title = id): Entity => ({ id, title, kind: id.split(':')[0] as Entity['kind'], domain: 'corp.test', href: '/assets', facts: [] })
const row = (e: Entity, reason = 'Прямое членство', source = 'AD'): Row => ({ id: e.id, title: e.title, target: e, reason, source, href: '/assets', observed_at: null, date_label: 'Снимок', facts: [] })
const section = (id: string, items: Row[], has_more = false): Section => ({ id, title: id, items, has_more, note: 'Сохранённые сведения' })
const dossier = (e: Entity, sections: Section[]): Dossier => ({ entity: e, sections, notes: [] })
const user = entity('user:1', 'Alice'), group = entity('group:1', 'Operators'), host = entity('host:1', 'PC1')
const fifty = dossier(user, [section('groups', Array.from({ length: 50 }, (_, i) => row(entity(`group:${i}`, `Group ${i}`)))), section('hosts', [row(host, 'Владелец', 'KSC')])])
const cache = { [user.id]: fifty }
test('initial graph is root and categories, not first twelve objects', () => {
  const graph = buildGraph(user.id, cache, initialState(user.id))
  assert.equal(graph.nodes.length, 3); assert.equal(graph.edges.length, 2)
  assert.equal(graph.nodes.find(n => n.category?.sectionId === 'groups')?.category?.count, 50)
  assert(!graph.nodes.some(n => n.id === host.id))
})
test('expanding a category shows all 50 groups and keeps other categories compact', () => {
  const state = initialState(user.id); state.expanded[categoryId(user.id, 'groups')] = true
  const graph = buildGraph(user.id, cache, state)
  assert.equal(graph.nodes.filter(n => n.kind === 'group').length, 50)
  assert(!graph.nodes.some(n => n.id === host.id)); assert(!graph.limited)
})
test('search finds collapsed rows and reveals only the selected path', () => {
  const hits = searchGraph(user.id, cache, 'gRoUp 49')
  assert.equal(hits.length, 1)
  const graph = buildGraph(user.id, cache, revealHit(initialState(user.id), hits[0]))
  assert.deepEqual(graph.nodes.filter(n => n.kind === 'group').map(n => n.id), ['group:49'])
})
test('search includes nested cached dossiers, identifiers and evidence', () => {
  const a = dossier(user, [section('groups', [row(group)])])
  const b = dossier(group, [section('members', [row(host, 'Вложенная связь')])])
  const all = { [user.id]: a, [group.id]: b }
  const hit = searchGraph(user.id, all, 'вложенная')[0]
  assert.equal(hit.node.id, host.id); assert.equal(hit.path.length, 2)
  const graph = buildGraph(user.id, all, revealHit(initialState(user.id), hit))
  assert(graph.nodes.some(n => n.id === host.id)); assert(graph.nodes.some(n => n.id === group.id))
})
test('category collapse preserves the category and nodes connected through another branch', () => {
  const a = dossier(user, [section('groups', [row(group)]), section('hosts', [row(host)])])
  const b = dossier(group, [section('members', [row(host), row(entity('host:2'))])])
  const all = { [user.id]: a, [group.id]: b }, state = initialState(user.id)
  for (const id of [categoryId(user.id,'groups'),categoryId(user.id,'hosts'),group.id,categoryId(group.id,'members')]) state.expanded[id] = true
  const graph = buildGraph(user.id, all, state), cat = graph.nodes.find(n => n.id === categoryId(group.id,'members'))!
  const collapsed = buildGraph(user.id, all, hideNode(state, cat, user.id))
  assert(collapsed.nodes.some(n => n.id === host.id)); assert(!collapsed.nodes.some(n => n.id === 'host:2')); assert(collapsed.nodes.some(n => n.id === cat.id))
})
test('hide object removes it; expanding its category restores it', () => {
  let state = initialState(user.id); state.expanded[categoryId(user.id,'groups')] = true
  let graph = buildGraph(user.id, cache, state)
  state = hideNode(state, graph.nodes.find(n => n.id === 'group:49')!, user.id)
  graph = buildGraph(user.id, cache, state); assert(!graph.nodes.some(n => n.id === 'group:49'))
  state = expandNode(state, graph.nodes.find(n => n.id === categoryId(user.id,'groups'))!, cache)
  assert(buildGraph(user.id, cache, state).nodes.some(n => n.id === 'group:49'))
})
test('canonical identities stay separate even for equal display names', () => {
  const a = dossier(user, [section('groups', [row(group), row(entity('group:2',group.title))])])
  const state = initialState(user.id); state.expanded[categoryId(user.id,'groups')] = true
  assert.equal(buildGraph(user.id,{[user.id]:a},state).nodes.filter(n=>n.kind==='group').length,2)
})
test('relationship evidence retains direction and indirect user CVE context', () => {
  const a = dossier(user,[section('hosts',[row(host,'Владелец','KSC')]),section('vulnerabilities',[{...row(host,'PC1','VM'),target:null,title:'CVE-2026-1'}])])
  const b = dossier(host,[section('users',[row(user,'Владелец','KSC')])])
  assert.equal(connections(a)[0].edge.id,connections(b)[0].edge.id)
  assert.equal(connections(a)[0].edge.label,'Связь с хостом')
  assert.equal(connections(a)[1].edge.label,'CVE связанного хоста')
})
test('KSC membership matches reverse direction; user group remains indirect', () => {
  const management = {...group,id:'kscgroup:1:12'}
  const a=dossier(host,[section('antivirus',[row(management,'Хост PC1','KSC')])])
  const b=dossier(management,[section('members',[row(host,'В группе KSC','KSC')])])
  assert.equal(connections(a)[0].edge.id,connections(b)[0].edge.id)
  assert.equal(connections(dossier(user,a.sections))[0].edge.label,'KSC связанного хоста')
})
test('leaf evidence is scoped by owner and observations are not relationships', () => {
  const leaf={...row(group),target:null}
  const a=dossier(user,[section('ad_policies',[leaf]),section('observations',[row(host)])])
  const b=dossier(host,[section('ad_policies',[leaf])])
  assert.equal(connections(a).length,1);assert.notEqual(connections(a)[0].node.id,connections(b)[0].node.id)
})
test('source and type filters apply to collapsed categories and preserve root', () => {
  const graph=buildGraph(user.id,cache,initialState(user.id))
  const filtered=filterGraph(graph,new Set(['host','user','group']),new Set(['KSC']))
  assert.deepEqual(filtered.nodes.map(n=>n.id),[user.id,categoryId(user.id,'hosts')])
  assert.equal(filterGraph(graph,new Set(),new Set()).nodes.length,1)
})
test('large category is blocked explicitly, never silently cut to a partial list', () => {
  const a=dossier(user,[section('groups',Array.from({length:MAX_NODES},(_,i)=>row(entity(`group:${i}`))),true)])
  const state=initialState(user.id);state.expanded[categoryId(user.id,'groups')]=true
  const graph=buildGraph(user.id,{[user.id]:a},state)
  assert(graph.limited);assert.equal(graph.nodes.filter(n=>n.kind==='group').length,0)
  assert(graph.blockedCategories.includes(categoryId(user.id,'groups')));assert(graph.sourceTruncated.includes(user.id))
  assert.equal(graph.nodes[1].category?.count,MAX_NODES)
})
test('cycles terminate and every visible node gets a distinct finite position', () => {
  const a=dossier(user,[section('groups',[row(group)])]),b=dossier(group,[section('members',[row(user)])])
  const state=initialState(user.id)
  for(const id of [categoryId(user.id,'groups'),group.id,categoryId(group.id,'members')])state.expanded[id]=true
  const graph=buildGraph(user.id,{[user.id]:a,[group.id]:b},state),positions=layoutGraph(graph)
  assert.equal(graph.nodes.length,4);assert.equal(new Set(Object.values(positions).map(p=>`${p.x}:${p.y}`)).size,4)
  assert(Object.values(positions).every(p=>Number.isFinite(p.x)&&Number.isFinite(p.y)))
})

test('a single search result can be revealed after an oversized category was blocked', () => {
  const a=dossier(user,[section('groups',Array.from({length:MAX_NODES},(_,i)=>row(entity(`group:${i}`,`Department ${i}`))))])
  const cache={ [user.id]:a },state=initialState(user.id);state.expanded[categoryId(user.id,'groups')]=true
  const hit=searchGraph(user.id,cache,'Department 499')[0]
  const graph=buildGraph(user.id,cache,revealHit(state,hit))
  assert(graph.nodes.some(n=>n.id==='group:499'));assert(!graph.limited)
  assert.equal(graph.nodes.filter(n=>n.kind==='group').length,1)
})
test('layout of all fifty groups has no overlapping coordinates', () => {
  const state=initialState(user.id);state.expanded[categoryId(user.id,'groups')]=true
  const graph=buildGraph(user.id,cache,state),positions=layoutGraph(graph)
  assert.equal(Object.keys(positions).length,graph.nodes.length)
  assert.equal(new Set(Object.values(positions).map(p=>`${p.x}:${p.y}`)).size,graph.nodes.length)
})
