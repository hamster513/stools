import { Link } from '@/lib/router'
import { reasons } from '../api/trends'

export function TrendBadge({ id, reason }: { id: string; reason: string }) {
  return <span className="inline-flex shrink-0" onClick={event => event.stopPropagation()} onKeyDown={event => event.stopPropagation()}><Link to={'/vm/trends?id=' + encodeURIComponent(id)}
    className="shrink-0 rounded bg-risk-high/10 px-1 text-[10px] font-semibold text-risk-high"
    title={reasons[reason] ?? 'Активный тренд'}>Тренд</Link></span>
}
