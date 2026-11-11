import type { Dossier, Entity, Row } from '../api.ts'

export const PAGE_SIZE = 12
export const MAX_NODES = 120
export const MAX_EDGES = 600
export const KIND_LABELS = { host: 'Хосты', user: 'Пользователи', group: 'Группы', policy: 'Политики', cve: 'Уязвимости', evidence: 'Другие сведения' }
export type NodeKind = keyof typeof KIND_LABELS
export interface GraphNode { id: string; title: string; kind: NodeKind; entity?: Entity; row?: Row }
export interface Evidence extends Row { note: string; context: string }
export interface Edge { id: string; from: string; to: string; kind: string; label: string; evidence: Evidence[] }
export interface Graph { rootId: string; nodes: GraphNode[]; edges: Edge[]; limited: boolean; sourceTruncated: string[] }
export interface Point { x: number; y: number }
export const sources = (source: string) => source.split(',').map(s => s.trim()).filter(Boolean)
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
    return { node, edge }
  }))
  // Interleave sections so large membership lists cannot hide all other relationships.
  return Array.from({ length: Math.max(0, ...queues.map(q => q.length)) }, (_, i) => queues.flatMap(q => q[i] ? [q[i]] : [])).flat()
}

export function buildGraph(rootId: string, dossiers: Record<string, Dossier>, shown: Record<string, number>): Graph {
  const root = dossiers[rootId]
  if (!root) return { rootId, nodes: [], edges: [], limited: false, sourceTruncated: [] }
  const nodes = new Map<string, GraphNode>([[rootId, entityNode(root.entity)]])
  const edges = new Map<string, Edge>(), visited = new Set<string>(), truncated = new Set<string>()
  const queue = [rootId]
  let limited = false
  while (queue.length) {
    const id = queue.shift()!
    if (visited.has(id)) continue
    visited.add(id)
    const dossier = dossiers[id]
    if (!dossier || !shown[id]) continue
    if (dossier.sections.some(s => s.id !== 'observations' && s.has_more)) truncated.add(id)
    for (const { node, edge } of connections(dossier).slice(0, shown[id])) {
      if (!edges.has(edge.id) && edges.size >= MAX_EDGES) { limited = true; continue }
      if (!nodes.has(node.id) && nodes.size >= MAX_NODES) { limited = true; continue }
      nodes.set(node.id, node)
      const previous = edges.get(edge.id)
      if (previous) {
        for (const item of edge.evidence) if (!previous.evidence.some(e => JSON.stringify(e) === JSON.stringify(item))) previous.evidence.push(item)
      } else edges.set(edge.id, edge)
      if (node.entity && !visited.has(node.id)) queue.push(node.id)
    }
  }
  return { rootId, nodes: [...nodes.values()], edges: [...edges.values()], limited, sourceTruncated: [...truncated] }
}

export function filterGraph(graph: Graph, kinds: Set<string>, enabledSources: Set<string>): Graph {
  const allowed = new Set(graph.nodes.filter(n => n.id === graph.rootId || kinds.has(n.kind)).map(n => n.id))
  const edges = graph.edges.filter(e => allowed.has(e.from) && allowed.has(e.to)).map(e => ({ ...e, evidence: e.evidence.filter(item => sources(item.source).some(s => enabledSources.has(s))) })).filter(e => e.evidence.length)
  const reachable = new Set([graph.rootId]), queue = [graph.rootId]
  while (queue.length) {
    const id = queue.shift()!
    for (const edge of edges) {
      const next = edge.from === id ? edge.to : edge.to === id ? edge.from : null
      if (next && !reachable.has(next)) { reachable.add(next); queue.push(next) }
    }
  }
  return { ...graph, nodes: graph.nodes.filter(n => reachable.has(n.id)), edges: edges.filter(e => reachable.has(e.from) && reachable.has(e.to)) }
}

export function layoutGraph(graph: Graph): Record<string, Point> {
  const positions: Record<string, Point> = { [graph.rootId]: { x: 0, y: 0 } }
  const depth = new Map([[graph.rootId, 0]]), queue = [graph.rootId], counts = new Map<number, number>()
  while (queue.length) {
    const id = queue.shift()!
    for (const edge of graph.edges) {
      const next = edge.from === id ? edge.to : edge.to === id ? edge.from : null
      if (!next || depth.has(next)) continue
      const level = depth.get(id)! + 1, index = counts.get(level) ?? 0
      counts.set(level, index + 1); depth.set(next, level); queue.push(next)
      const slot = Math.floor(index / 2), y = slot === 0 ? 0 : Math.ceil(slot / 2) * 105 * (slot % 2 ? -1 : 1)
      positions[next] = { x: (index % 2 ? -1 : 1) * level * 330, y }
    }
  }
  return positions
}
