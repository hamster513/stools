import { FileText, X } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Link } from '@/lib/router'
import { ObjectIcon } from '../ObjectIcon'
import type { Graph, GraphNode } from './model'
export function NodeDetails({ node, graph, pending, onPreview, onClose }: { node: GraphNode; graph: Graph; pending: boolean; onPreview: () => void; onClose: () => void }) {
  const related = graph.edges.filter(edge => edge.relation && (edge.relation.from === node.id || edge.relation.to === node.id))
  return <aside aria-label="Сведения об узле" className="max-h-[710px] min-w-0 space-y-4 overflow-y-auto border-t border-grid bg-surface p-4 xl:border-l xl:border-t-0">
    <div className="flex items-start gap-2"><ObjectIcon kind={node.kind} /><div className="min-w-0 flex-1"><p className="mb-1 text-xs text-text-secondary">Выбранный объект{node.id === graph.rootId ? ' · начало графа' : ''}</p><h3 className="break-words font-semibold">{node.title}</h3>{node.entity?.domain && <p className="mt-1 break-all text-xs text-text-secondary">{node.entity.domain}</p>}</div><Button variant="ghost" aria-label="Закрыть сведения об узле" onClick={onClose}><X size={16} /></Button></div>
    <dl className="space-y-1 text-xs">{(node.entity?.facts ?? node.row?.facts ?? []).map(f => <div key={f.label}><dt className="inline text-text-secondary">{f.label}: </dt><dd className="inline break-words">{f.value}</dd></div>)}</dl>
    {node.entity && <Button disabled={pending} onClick={onPreview}><FileText size={14} />Досье узла</Button>}
    {(node.entity?.href || node.row?.href) && <Link to={(node.entity?.href ?? node.row?.href)!} className="block text-xs text-primary hover:underline">Открыть источник ↗</Link>}
    <details open={related.length === 1} className="space-y-3"><summary className="cursor-pointer text-sm font-medium">Основания видимых связей ({related.length})</summary>
      {!related.length && <p className="text-xs text-text-secondary">Раскройте категорию связей или откройте досье узла.</p>}
      {related.map(edge => {
        const neighborId = edge.relation!.from === node.id ? edge.relation!.to : edge.relation!.from
        return <details key={edge.id} open={related.length === 1} className="space-y-2 border-t border-grid pt-3 text-xs"><summary className="cursor-pointer font-medium">{edge.label} · {graph.nodes.find(n => n.id === neighborId)?.title ?? edge.evidence[0]?.context}</summary>
          {edge.evidence.map((item, i) => <div key={i} className="space-y-1 break-words"><p>{item.reason}</p><p className="text-text-secondary">{item.note}</p><p className="text-text-secondary">Контекст: {item.context}</p>{item.facts.map(f => <p key={f.label}>{f.label}: {f.value}</p>)}<p><Link className="text-primary hover:underline" to={item.href}>{item.source} ↗</Link> · {item.date_label}: {item.observed_at ? new Date(item.observed_at).toLocaleString('ru-RU') : 'дата не указана'}</p></div>)}
        </details>
      })}
    </details>
  </aside>
}
