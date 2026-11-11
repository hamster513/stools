import { forwardRef, useEffect, useId, useImperativeHandle, useMemo, useRef, useState, type PointerEvent } from 'react'
import { Focus, Minus, MoreHorizontal, Plus, RotateCcw } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { ObjectIcon } from '../ObjectIcon'
import { layoutGraph, type Graph, type GraphNode, type Point } from './model'

const LABELS = { host: 'Хост', user: 'Пользователь', group: 'Группа', policy: 'Политика', cve: 'Уязвимость', evidence: 'Сведения', category: 'Категория' }
const short = (text: string, length: number) => text.length > length ? `${text.slice(0, length - 1)}…` : text
interface Camera extends Point { zoom: number }
function fitted(points: Record<string, Point>): Camera {
  const values = Object.values(points)
  if (!values.length) return { x: 0, y: 0, zoom: 1 }
  const xs = values.map(p => p.x), ys = values.map(p => p.y)
  const left = Math.min(...xs) - 140, right = Math.max(...xs) + 140, top = Math.min(...ys) - 80, bottom = Math.max(...ys) + 80
  return { x: (left + right) / 2, y: (top + bottom) / 2, zoom: Math.max(.08, Math.min(1, 1000 / (right - left), 600 / (bottom - top))) }
}
export interface CanvasHandle { focus: (id: string) => void }
interface Props {
  graph: Graph; selected: string | null; onSelect: (id: string | null) => void
  onMenu: (node: GraphNode, point: Point, trigger: Element) => void
}
export const GraphCanvas = forwardRef<CanvasHandle, Props>(function GraphCanvas({ graph, selected, onSelect, onMenu }, ref) {
  const marker = useId().replace(/:/g, '')
  const svg = useRef<SVGSVGElement>(null)
  const layout = useMemo(() => layoutGraph(graph), [graph])
  const [manual, setManual] = useState<Record<string, Point>>({})
  const points = useMemo(() => Object.fromEntries(graph.nodes.map(n => [n.id, manual[n.id] ?? layout[n.id] ?? { x: 0, y: 0 }])), [graph.nodes, manual, layout])
  const viewKey = graph.nodes.map(n => n.id).join('|')
  const [view, setView] = useState<{ key: string; camera: Camera } | null>(null)
  const camera = view?.key === viewKey ? view.camera : fitted(points)
  function setCamera(next: Camera) { setView({ key: viewKey, camera: next }) }
  useImperativeHandle(ref, () => ({ focus(id) {
    if (!points[id]) return
    setView({ key: viewKey, camera: { ...points[id], zoom: 1 } })
    const node = [...(svg.current?.querySelectorAll<SVGGElement>('[data-node-id]') ?? [])].find(n => n.dataset.nodeId === id)
    node?.focus({ preventScroll: true })
  } }), [points, viewKey])
  useEffect(() => {
    const element = svg.current
    if (!element) return
    const wheel = (event: WheelEvent) => {
      event.preventDefault()
      setView(current => {
        const camera = current?.key === viewKey ? current.camera : fitted(points)
        return { key: viewKey, camera: { ...camera, zoom: Math.min(2.5, Math.max(.08, camera.zoom * Math.exp(-Math.max(-100, Math.min(100, event.deltaY)) * .005))) } }
      })
    }
    element.addEventListener('wheel', wheel, { passive: false })
    return () => element.removeEventListener('wheel', wheel)
  }, [viewKey, points])
  const drag = useRef<{ id: string | null; start: Point; original: Point; scale: number; pointer: number; moved: boolean } | null>(null)
  function down(e: PointerEvent<SVGSVGElement>) {
    if (e.button !== 0) return
    const id = (e.target as Element).closest('[data-node-id]')?.getAttribute('data-node-id') ?? null
    drag.current = { id, start: { x: e.clientX, y: e.clientY }, original: id ? points[id] : camera, scale: svg.current?.getScreenCTM()?.a ?? 1, pointer: e.pointerId, moved: false }
    e.currentTarget.setPointerCapture(e.pointerId)
  }
  function move(e: PointerEvent<SVGSVGElement>) {
    const d = drag.current
    if (!d || d.pointer !== e.pointerId) return
    const dx = (e.clientX - d.start.x) / d.scale, dy = (e.clientY - d.start.y) / d.scale
    if (Math.hypot(e.clientX - d.start.x, e.clientY - d.start.y) < 3 && !d.moved) return
    d.moved = true
    if (d.id) setManual(p => ({ ...p, [d.id!]: { x: d.original.x + dx, y: d.original.y + dy } }))
    else setCamera({ ...camera, x: d.original.x - dx, y: d.original.y - dy })
  }
  function up(e: PointerEvent<SVGSVGElement>) {
    const d = drag.current
    if (d?.pointer === e.pointerId && !d.moved) onSelect(d.id)
    if (e.currentTarget.hasPointerCapture(e.pointerId)) e.currentTarget.releasePointerCapture(e.pointerId)
    drag.current = null
  }
  function zoom(factor: number) { setCamera({ ...camera, zoom: Math.min(2.5, Math.max(.08, camera.zoom * factor)) }) }
  return <div className="min-w-0">
    <div className="flex flex-wrap items-center gap-2 border-b border-grid p-2">
      <Button aria-label="Уменьшить масштаб" onClick={() => zoom(1 / 1.25)}><Minus size={15} /></Button>
      <span className="w-12 text-center text-xs tabular-nums">{Math.round(camera.zoom * 100)}%</span>
      <Button aria-label="Увеличить масштаб" onClick={() => zoom(1.25)}><Plus size={15} /></Button>
      <Button onClick={() => setCamera(fitted(points))}><Focus size={15} />Вписать</Button>
      <Button onClick={() => { setManual({}); setCamera(fitted(layout)) }}><RotateCcw size={15} />Сбросить расположение</Button>
      <Button disabled={!selected} onClick={e => { const node = graph.nodes.find(n => n.id === selected); if (node) { const r = e.currentTarget.getBoundingClientRect(); onMenu(node, { x: r.left, y: r.bottom }, e.currentTarget) } }}><MoreHorizontal size={15} />Действия узла</Button>
    </div>
    <svg ref={svg} role="group" aria-label="Граф связей" className="h-[600px] w-full touch-none select-none bg-app-bg"
      viewBox={`${camera.x - 500 / camera.zoom} ${camera.y - 300 / camera.zoom} ${1000 / camera.zoom} ${600 / camera.zoom}`}
      onPointerDown={down} onPointerMove={move} onPointerUp={up} onPointerCancel={() => { drag.current = null }}>
      <defs><marker id={marker} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="currentColor" className="text-text-secondary" /></marker></defs>
      {graph.edges.map(edge => {
        const a = points[edge.from], b = points[edge.to], dx = b.x - a.x, dy = b.y - a.y
        const offset = Math.min(dx ? 110 / Math.abs(dx) : Infinity, dy ? 36 / Math.abs(dy) : Infinity, .48), active = edge.from === selected || edge.to === selected
        return <g key={edge.id} pointerEvents="none" data-edge-id={edge.id}>
          <line x1={a.x + dx * offset} y1={a.y + dy * offset} x2={b.x - dx * offset} y2={b.y - dy * offset} markerEnd={`url(#${marker})`} className={active ? 'stroke-primary' : 'stroke-border'} strokeWidth={active ? 2 : 1.5} />
          {active && edge.label && <text x={(a.x + b.x) / 2} y={(a.y + b.y) / 2 - 9} textAnchor="middle" className="fill-text-secondary stroke-app-bg" paintOrder="stroke" strokeWidth="5" fontSize="11">{edge.label}</text>}
        </g>
      })}
      {graph.nodes.map(node => {
        const p = points[node.id], active = node.id === selected, iconKind = node.category?.objectKind ?? node.kind
        return <g key={node.id} data-node-id={node.id} data-node-kind={node.kind} role="button" tabIndex={0} aria-label={`${LABELS[node.kind]}: ${node.title}${node.category ? ` (${node.category.count}${node.category.hasMore ? '+' : ''})` : ''}`} aria-pressed={active} aria-haspopup="menu"
          transform={`translate(${p.x},${p.y})`} className="cursor-grab outline-none focus-visible:[&>rect]:stroke-primary" onClick={e => { if (e.detail === 0) onSelect(node.id) }}
          onContextMenu={e => { e.preventDefault(); onMenu(node, { x: e.clientX, y: e.clientY }, e.currentTarget) }}
          onKeyDown={e => {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(node.id) }
            if (e.key === 'ContextMenu' || e.shiftKey && e.key === 'F10') { e.preventDefault(); const r = e.currentTarget.getBoundingClientRect(); onMenu(node, { x: r.left + r.width / 2, y: r.top + r.height / 2 }, e.currentTarget) }
            const delta: Record<string, Point> = { ArrowLeft: { x: -15, y: 0 }, ArrowRight: { x: 15, y: 0 }, ArrowUp: { x: 0, y: -15 }, ArrowDown: { x: 0, y: 15 } }
            if (delta[e.key]) { e.preventDefault(); setManual(m => ({ ...m, [node.id]: { x: p.x + delta[e.key].x, y: p.y + delta[e.key].y } })) }
          }}>
          <title>{node.title}{node.entity?.domain ? ` · ${node.entity.domain}` : ''}{node.category ? ` · показано ${node.category.visible} из ${node.category.count}${node.category.hasMore ? '+' : ''}` : ''}</title>
          <rect x="-108" y="-35" width="216" height="70" rx="8" className={`fill-surface ${active ? 'stroke-primary' : 'stroke-border'}`} strokeDasharray={node.category ? '5 3' : undefined} strokeWidth={active || node.id === graph.rootId ? 2.5 : 1.5} />
          <g transform="translate(-94,-12)" className="text-primary" data-object-icon={iconKind}><ObjectIcon kind={iconKind} size={24} /></g>
          <text x="-58" y="-10" fontSize="11" className="fill-text-secondary">{node.category ? `Категория · ${node.category.visible}/${node.category.count}${node.category.hasMore ? '+' : ''}` : LABELS[node.kind]}{node.id === graph.rootId ? ' · начало' : ''}</text>
          <text x="-58" y="12" fontSize="12" fontWeight="500" className="fill-text">{short(node.title, 21)}</text>
        </g>
      })}
    </svg>
    <p className="border-t border-grid px-3 py-2 text-xs text-text-secondary">Правая кнопка мыши → раскрыть или скрыть. С клавиатуры — Shift+F10; на сенсорном экране — «Действия узла». Клик по фону закрывает сведения.</p>
  </div>
})
