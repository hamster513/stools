import type { Dossier, Entity, Row } from '../api.ts'
import { matchesRow, matchesEntity } from '../searchText.ts'
import { SECTION_KINDS } from '../sectionKinds.ts'

export const MAX_NODES = 500
export const MAX_EDGES = 1500
export const KIND_LABELS = { host: 'Хосты', user: 'Пользователи', group: 'Группы', policy: 'Политики', cve: 'Уязвимости', evidence: 'Другие сведения' }
export type ObjectKind = keyof typeof KIND_LABELS
export type NodeKind = ObjectKind | 'category'
export interface Category { ownerId: string; sectionId: string; count: number; total: number; visible: number; hasMore: boolean; objectKind: ObjectKind }
export interface GraphNode { id: string; title: string; kind: NodeKind; entity?: Entity; row?: Row; category?: Category }
export interface Evidence extends Row { note: string; context: string; nodeId?: string; objectKind?: ObjectKind }
export interface Edge { id: string; from: string; to: string; kind: string; label: string; evidence: Evidence[]; relation?: { from: string; to: string } }
export interface Graph { rootId: string; nodes: GraphNode[]; edges: Edge[]; limited: boolean; blockedCategories: string[]; sourceTruncated: string[] }
export interface Point { x: number; y: number }
export interface GraphState { expanded: Record<string, boolean>; revealed: Record<string, string[]>; hidden: string[] }
export interface SearchHit { node: GraphNode; path: { ownerId: string; categoryId: string; targetId: string }[]; context: string }
export const sources = (source: string) => source.split(',').map(s => s.trim()).filter(Boolean)
export const categoryId = (ownerId: string, sectionId: string) => JSON.stringify(['category', ownerId, sectionId])
export const initialState = (rootId: string): GraphState => ({ expanded: { [rootId]: true }, revealed: {}, hidden: [] })
const entityNode = (entity: Entity): GraphNode => ({ ...entity, entity })

export function connections(dossier: Dossier) {
  const root = dossier.entity
  const queues = dossier.sections.filter(s => s.id !== 'observations').map(section => section.items.map(row => {
    const node: GraphNode = row.target ? entityNode(row.target) : {
      id: JSON.stringify(['evidence', root.id, section.id, row.id]), title: row.title, row,
      kind: section.id === 'vulnerabilities' ? 'cve' : ['ad_policies', 'antivirus'].includes(section.id) ? 'policy' : 'evidence',
    }
    let kind = section.id, label = section.title, from = root.id, to = node.id
    if (['groups', 'members'].includes(section.id)) {
      kind = 'membership'; label = (section.id === 'members' ? root.id : node.id).startsWith('kscgroup:') ? 'Группа KSC' : 'Членство в группе'
      if (section.id === 'members') { from = node.id; to = root.id }
    } else if (['users', 'hosts'].includes(section.id)) {
      kind = 'user_host'; label = 'Связь с хостом'
      if (section.id === 'users') { from = node.id; to = root.id }
    } else if (section.id === 'ad_policies') label = 'Область GPO'
    else if (section.id === 'antivirus') {
      if (node.entity?.id.startsWith('kscgroup:')) {
        label = root.kind === 'host' ? 'Группа KSC' : 'KSC связанного хоста'
        kind = root.kind === 'host' ? 'membership' : 'related_host_ksc'
      } else label = root.kind === 'user' ? 'KSC связанного хоста' : 'Политика / группа KSC'
    }
    else if (section.id === 'vulnerabilities') label = root.kind === 'host' ? 'Находка VM' : 'CVE связанного хоста'
    const edge: Edge = { id: JSON.stringify([kind, from, to]), from, to, kind, label, evidence: [{ ...row, note: section.note, context: root.title }] }
    return { node, edge, sectionId: section.id }
  }))
  // Interleave sections so large membership lists cannot hide all other relationships.
  return Array.from({ length: Math.max(0, ...queues.map(q => q.length)) }, (_, i) => queues.flatMap(q => q[i] ? [q[i]] : [])).flat()
}

export function categories(dossier: Dossier) {
  const all = connections(dossier)
  return dossier.sections.filter(s => s.id !== 'observations' && s.items.length).map(section => {
    const unique = new Map<string, typeof all[number]>()
    for (const item of all.filter(c => c.sectionId === section.id)) {
      const previous = unique.get(item.node.id)
      if (previous) previous.edge.evidence.push(...item.edge.evidence)
      else unique.set(item.node.id, item)
    }
    const items = [...unique.values()]
    const node: GraphNode = {
      id: categoryId(dossier.entity.id, section.id), title: section.title, kind: 'category',
      category: { ownerId: dossier.entity.id, sectionId: section.id, count: items.length, total: items.length, visible: 0, hasMore: section.has_more, objectKind: SECTION_KINDS[section.id] ?? 'evidence' },
    }
    return { node, items }
  })
}

export function buildGraph(rootId: string, dossiers: Record<string, Dossier>, state: GraphState): Graph {
  const root = dossiers[rootId]
  const graph: Graph = { rootId, nodes: [], edges: [], limited: false, blockedCategories: [], sourceTruncated: [] }
  if (!root) return graph
  const nodes = new Map<string, GraphNode>([[rootId, entityNode(root.entity)]])
  const edges = new Map<string, Edge>(), visited = new Set<string>(), hidden = new Set(state.hidden), queue = [rootId]
  while (queue.length) {
    const id = queue.shift()!
    if (visited.has(id)) continue
    visited.add(id)
    const dossier = dossiers[id]
    if (!dossier) continue
    if (dossier.sections.some(s => s.id !== 'observations' && s.has_more)) graph.sourceTruncated.push(id)
    if (!state.expanded[id]) continue
    for (const { node: category, items } of categories(dossier)) {
      if (nodes.size >= MAX_NODES || edges.size >= MAX_EDGES) { graph.limited = true; continue }
      nodes.set(category.id, category)
      edges.set(category.id, { id: category.id, from: id, to: category.id, kind: 'category', label: '', evidence: items.flatMap(item => item.edge.evidence.map(e => ({ ...e, nodeId: item.node.id, objectKind: item.node.kind as ObjectKind }))) })
      const selected = new Set(state.revealed[category.id] ?? [])
      const requested = items.filter(item => !hidden.has(item.node.id) && (state.expanded[category.id] || selected.has(item.node.id)))
      // A category is atomic: a displayed count must never disguise a silently truncated list.
      const needed = requested.filter(item => !nodes.has(item.node.id)).length
      if (nodes.size + needed > MAX_NODES || edges.size + requested.length > MAX_EDGES) {
        graph.limited = true; graph.blockedCategories.push(category.id); continue
      }
      category.category!.visible = requested.length
      for (const { node, edge } of requested) {
        if (!nodes.has(node.id)) nodes.set(node.id, node)
        const edgeId = JSON.stringify([category.id, edge.id])
        edges.set(edgeId, { ...edge, id: edgeId, from: category.id, to: node.id, relation: { from: edge.from, to: edge.to }, evidence: edge.evidence.map(e => ({ ...e, nodeId: node.id, objectKind: node.kind as ObjectKind })) })
        if (node.entity && !visited.has(node.id)) queue.push(node.id)
      }
    }
  }
  return { ...graph, nodes: [...nodes.values()], edges: [...edges.values()] }
}

export function expandNode(state: GraphState, node: GraphNode, dossiers: Record<string, Dossier>): GraphState {
  const restored = new Set([node.id])
  if (node.category) for (const item of categories(dossiers[node.category.ownerId]).find(c => c.node.id === node.id)?.items ?? []) restored.add(item.node.id)
  return { ...state, expanded: { ...state.expanded, [node.id]: true }, hidden: state.hidden.filter(id => !restored.has(id)) }
}
export function hideNode(state: GraphState, node: GraphNode, rootId: string): GraphState {
  if (node.id === rootId) return { expanded: {}, revealed: {}, hidden: [] }
  if (node.category) return { ...state, expanded: { ...state.expanded, [node.id]: false }, revealed: { ...state.revealed, [node.id]: [] } }
  return { ...state, expanded: { ...state.expanded, [node.id]: false }, hidden: [...new Set([...state.hidden, node.id])] }
}
export function revealHit(state: GraphState, hit: SearchHit): GraphState {
  const expanded = { ...state.expanded }, revealed = { ...state.revealed }, restored = new Set([hit.node.id])
  for (const step of hit.path) {
    expanded[step.ownerId] = true
    expanded[step.categoryId] = false
    revealed[step.categoryId] = [...new Set([...(revealed[step.categoryId] ?? []), step.targetId])]
    restored.add(step.ownerId); restored.add(step.targetId)
  }
  if (hit.node.category) expanded[hit.node.category.ownerId] = true
  return { expanded, revealed, hidden: state.hidden.filter(id => !restored.has(id)) }
}

export function searchGraph(rootId: string, dossiers: Record<string, Dossier>, query: string): SearchHit[] {
  if (!query.trim() || !dossiers[rootId]) return []
  const result = new Map<string, SearchHit>(), visited = new Set<string>()
  const queue: { id: string; path: SearchHit['path'] }[] = [{ id: rootId, path: [] }]
  const root = dossiers[rootId].entity
  if (matchesEntity(root, query)) result.set(rootId, { node: entityNode(root), path: [], context: 'Начальный объект' })
  while (queue.length) {
    const { id, path } = queue.shift()!
    if (visited.has(id)) continue
    visited.add(id)
    const dossier = dossiers[id]
    if (!dossier) continue
    for (const { node: category, items } of categories(dossier)) {
      if (category.title.toLocaleLowerCase().includes(query.trim().toLocaleLowerCase())) result.set(category.id, { node: category, path, context: dossier.entity.title })
      for (const item of items) {
        const next = [...path, { ownerId: id, categoryId: category.id, targetId: item.node.id }]
        if (!result.has(item.node.id) && item.edge.evidence.some(row => matchesRow(row, query))) result.set(item.node.id, { node: item.node, path: next, context: `${dossier.entity.title} · ${category.title}` })
        if (item.node.entity && !visited.has(item.node.id)) queue.push({ id: item.node.id, path: next })
      }
    }
  }
  return [...result.values()]
}

export function filterGraph(graph: Graph, kinds: Set<string>, enabledSources: Set<string>): Graph {
  const allowed = new Set(graph.nodes.filter(n => n.id === graph.rootId || n.category || kinds.has(n.kind)).map(n => n.id))
  const edges = graph.edges.filter(e => allowed.has(e.from) && allowed.has(e.to)).map(e => ({ ...e, evidence: e.evidence.filter(item => (!item.objectKind || kinds.has(item.objectKind)) && sources(item.source).some(s => enabledSources.has(s))) })).filter(e => e.evidence.length)
  const reachable = new Set([graph.rootId]), queue = [graph.rootId]
  while (queue.length) {
    const id = queue.shift()!
    for (const edge of edges) {
      const next = edge.from === id ? edge.to : edge.to === id ? edge.from : null
      if (next && !reachable.has(next)) { reachable.add(next); queue.push(next) }
    }
  }
  return { ...graph, nodes: graph.nodes.filter(n => reachable.has(n.id)).map(n => n.category ? { ...n, category: { ...n.category, count: new Set(edges.find(e => e.id === n.id)?.evidence.map(e => e.nodeId)).size, visible: edges.filter(e => e.from === n.id).length } } : n), edges: edges.filter(e => reachable.has(e.from) && reachable.has(e.to)) }
}

export function layoutGraph(graph: Graph): Record<string, Point> {
  // Follow the exploration direction; cycles cannot move discovered nodes back a level.
  const outgoing = new Map<string, string[]>()
  for (const edge of graph.edges) outgoing.set(edge.from, [...(outgoing.get(edge.from) ?? []), edge.to])
  const depth = new Map([[graph.rootId, 0]]), queue = [graph.rootId]
  const levels: string[][] = [[graph.rootId]]
  for (let index = 0; index < queue.length; index++) {
    const id = queue[index], level = depth.get(id)! + 1
    for (const next of outgoing.get(id) ?? []) {
      if (depth.has(next)) continue
      depth.set(next, level); queue.push(next)
      const peers = levels[level] ?? (levels[level] = [])
      peers.push(next)
    }
  }
  const detached = graph.nodes.filter(node => !depth.has(node.id)).map(node => node.id)
  if (detached.length) levels.push(detached)
  const positions: Record<string, Point> = {}
  levels.forEach((ids, level) => ids.forEach((id, index) => {
    positions[id] = { x: level * 360, y: (index - (ids.length - 1) / 2) * 100 }
  }))
  return positions
}
