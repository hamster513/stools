import { ArrowUpRight } from 'lucide-react'
import { Link } from '@/lib/router'
import { ObjectIcon } from './ObjectIcon'
import type { Entity, Row } from './api'
export function EvidenceTable({ rows, onOpen }: { rows: Row[]; onOpen: (entity: Entity) => void }) {
  return <div className="overflow-x-auto"><table className="w-full min-w-[640px] table-fixed text-left text-sm">
    <colgroup><col className="w-[30%]" /><col className="w-[50%]" /><col className="w-[20%]" /></colgroup>
    <thead className="text-xs text-text-secondary"><tr className="border-b border-grid">
      <th className="py-2 pr-4 font-medium">Объект</th><th className="py-2 pr-4 font-medium">Сведения</th><th className="py-2 font-medium">Источник и дата</th>
    </tr></thead>
    <tbody>{rows.map(row => <tr key={row.id} className="border-b border-grid align-top last:border-0">
      <td className="max-w-xs py-3 pr-4 break-words">
        {row.target ? <button type="button" className="inline-flex items-start gap-2 text-left font-medium text-primary hover:underline" onClick={() => onOpen(row.target!)}><ObjectIcon kind={row.target.kind} size={15} /><span>{row.title}</span></button> : <span className="font-medium">{row.title}</span>}
        {row.target?.domain && <p className="mt-1 text-xs text-text-secondary">{row.target.domain}</p>}
      </td>
      <td className="max-w-xl py-3 pr-4 break-words"><p>{row.reason}</p>
        {row.facts.length > 0 && <dl className="mt-1 space-y-1 text-xs">{row.facts.map(f => <div key={f.label}><dt className="inline text-text-secondary">{f.label}: </dt><dd className="inline whitespace-pre-wrap">{f.value}</dd></div>)}</dl>}
      </td>
      <td className="w-52 py-3 text-xs text-text-secondary"><Link to={row.href} className="inline-flex items-center gap-1 text-primary hover:underline">{row.source === row.title ? 'Открыть' : row.source}<ArrowUpRight size={12} aria-hidden /></Link>
        <p className="mt-1">{row.observed_at ? new Date(row.observed_at).toLocaleString('ru-RU') : 'Дата не указана источником'}</p>
      </td>
    </tr>)}</tbody>
  </table></div>
}
