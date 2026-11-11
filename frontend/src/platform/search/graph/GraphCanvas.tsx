import { useEffect, useId, useMemo, useRef, useState, type PointerEvent } from 'react'
import { Focus, Minus, Plus, RotateCcw } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { layoutGraph, type Graph, type Point, type NodeKind } from './model'

const COLORS: Record<NodeKind, string> = { host: '#60a5fa', user: '#c084fc', group: '#2dd4bf', policy: '#fbbf24', cve: '#fb7185', evidence: '#94a3b8' }
const LABELS: Record<NodeKind, string> = { host: 'Хост', user: 'Пользователь', group: 'Группа', policy: 'Политика', cve: 'Уязвимость', evidence: 'Сведения' }
const short = (text: string, length: number) => text.length > length ? `${text.slice(0, length - 1)}…` : text
function fitted(points: Record<string, Point>) {
  const values = Object.values(points)
  if (!values.length) return { x: 0, y: 0, zoom: 1 }
  const xs = values.map(p => p.x), ys = values.map(p => p.y)
  const left = Math.min(...xs) - 130, right = Math.max(...xs) + 130, top = Math.min(...ys) - 70, bottom = Math.max(...ys) + 70
  return { x: (left + right) / 2, y: (top + bottom) / 2, zoom: Math.max(.12, Math.min(1, 1000 / (right - left), 600 / (bottom - top))) }
}
export function GraphCanvas({ graph, selected, onSelect }: { graph: Graph; selected: string; onSelect: (id: string) => void }) {
  const marker = useId().replace(/:/g, '')
  const svg = useRef<SVGSVGElement>(null)
  const layout = useMemo(() => layoutGraph(graph), [graph])
  const [manual, setManual] = useState<Record<string, Point>>({})
  const points = Object.fromEntries(graph.nodes.map(n => [n.id, manual[n.id] ?? layout[n.id] ?? { x: 0, y: 0 }]))
  const [camera, setCamera] = useState(() => fitted(layout))
  useEffect(() => {
    const element = svg.current
    if (!element) return
    const wheel = (event: WheelEvent) => {
      event.preventDefault()
      setCamera(c => ({ ...c, zoom: Math.min(2.5, Math.max(.12, c.zoom * Math.exp(-Math.max(-100, Math.min(100, event.deltaY)) * .005))) }))
    }
    element.addEventListener('wheel', wheel, { passive: false })
    return () => element.removeEventListener('wheel', wheel)
  }, [])
  const drag = useRef<{ id: string | null; start: Point; original: Point; scale: number; pointer: number } | null>(null)
  function down(e: PointerEvent<SVGSVGElement>) {
    if (e.button !== 0) return
    const id = (e.target as Element).closest('[data-node-id]')?.getAttribute('data-node-id') ?? null
    if (id) onSelect(id)
    const scale = svg.current?.getScreenCTM()?.a ?? 1
    drag.current = { id, start: { x: e.clientX, y: e.clientY }, original: id ? points[id] : camera, scale, pointer: e.pointerId }
    e.currentTarget.setPointerCapture(e.pointerId)
  }
  function move(e: PointerEvent<SVGSVGElement>) {
    const d = drag.current
    if (!d || d.pointer !== e.pointerId) return
    const dx = (e.clientX - d.start.x) / d.scale, dy = (e.clientY - d.start.y) / d.scale
    if (d.id) setManual(p => ({ ...p, [d.id!]: { x: d.original.x + dx, y: d.original.y + dy } }))
    else setCamera(c => ({ ...c, x: d.original.x - dx, y: d.original.y - dy }))
  }
  function zoom(factor: number) { setCamera(c => ({ ...c, zoom: Math.min(2.5, Math.max(.12, c.zoom * factor)) })) }
  return <div className="min-w-0">
    <div className="flex flex-wrap items-center gap-2 border-b border-grid p-2">
      <Button aria-label="Уменьшить масштаб" onClick={() => zoom(1 / 1.25)}><Minus size={15} /></Button>
      <span className="w-12 text-center text-xs tabular-nums">{Math.round(camera.zoom * 100)}%</span>
      <Button aria-label="Увеличить масштаб" onClick={() => zoom(1.25)}><Plus size={15} /></Button>
      <Button onClick={() => setCamera(fitted(points))}><Focus size={15} />Вписать</Button>
      <Button onClick={() => { setManual({}); setCamera(fitted(layout)) }}><RotateCcw size={15} />Сбросить расположение</Button>
    </div>
    <svg ref={svg} role="group" aria-label="Граф связей" className="h-[540px] w-full touch-none select-none bg-app-bg"
      viewBox={`${camera.x - 500 / camera.zoom} ${camera.y - 300 / camera.zoom} ${1000 / camera.zoom} ${600 / camera.zoom}`}
      onPointerDown={down} onPointerMove={move} onPointerUp={() => { drag.current = null }} onPointerCancel={() => { drag.current = null }}>
      <defs><marker id={marker} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="currentColor" className="text-text-secondary" /></marker></defs>
      {graph.edges.map(edge => {
        const a = points[edge.from], b = points[edge.to], dx = b.x - a.x, dy = b.y - a.y
        const boundary = (x: number, y: number) => Math.min(x ? 96 / Math.abs(x) : Infinity, y ? 32 / Math.abs(y) : Infinity, .48)
        const offset = boundary(dx, dy), active = edge.from === selected || edge.to === selected
        return <g key={edge.id} pointerEvents="none" data-edge-id={edge.id}>
          <line x1={a.x + dx * offset} y1={a.y + dy * offset} x2={b.x - dx * offset} y2={b.y - dy * offset} markerEnd={`url(#${marker})`} className={active ? 'stroke-primary' : 'stroke-border'} strokeWidth={active ? 2 : 1.5} />
          <text x={(a.x + b.x) / 2} y={(a.y + b.y) / 2 - 8} textAnchor="middle" className="fill-text-secondary stroke-app-bg" paintOrder="stroke" strokeWidth="5" fontSize="10">{edge.label}</text>
        </g>
      })}
      {graph.nodes.map(node => {
        const p = points[node.id], active = node.id === selected
        return <g key={node.id} data-node-id={node.id} role="button" tabIndex={0} aria-label={`${LABELS[node.kind]}: ${node.title}`} aria-pressed={active}
          transform={`translate(${p.x},${p.y})`} className="cursor-grab outline-none focus-visible:[&>rect]:stroke-primary" onClick={() => onSelect(node.id)}
          onKeyDown={e => {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(node.id) }
            const delta: Record<string, Point> = { ArrowLeft: { x: -15, y: 0 }, ArrowRight: { x: 15, y: 0 }, ArrowUp: { x: 0, y: -15 }, ArrowDown: { x: 0, y: 15 } }
            if (delta[e.key]) { e.preventDefault(); setManual(m => ({ ...m, [node.id]: { x: p.x + delta[e.key].x, y: p.y + delta[e.key].y } })) }
          }}>
          <title>{node.title}{node.entity?.domain ? ` · ${node.entity.domain}` : ''}</title>
          <rect x="-94" y="-30" width="188" height="60" rx="8" className={`fill-surface ${active ? 'stroke-primary' : 'stroke-border'}`} strokeWidth={active || node.id === graph.rootId ? 2.5 : 1.5} />
          <circle cx="-78" cy="-11" r="4" fill={COLORS[node.kind]} />
          <text x="-66" y="-7" fontSize="11" className="fill-text-secondary">{LABELS[node.kind]}{node.id === graph.rootId ? ' · начало' : ''}</text>
          <text x="-78" y="15" fontSize="12" fontWeight="500" className="fill-text">{short(node.title, 23)}</text>
        </g>
      })}
    </svg>
    <p className="border-t border-grid px-3 py-2 text-xs text-text-secondary">Выберите узел, чтобы увидеть связи. Перетаскивайте узлы или фон, колесо меняет масштаб; стрелки клавиатуры перемещают узел.</p>
  </div>
}
