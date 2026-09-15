import type { AttackRuleBrief } from '@/modules/siem/api/types'
import { AttentionBadge, attentionLevel } from '@/modules/siem/components/ui/AttentionBadge'
import { Link } from '@/lib/router'

/**
 * Правила с маркировкой. Одних имён мало: разметка группы, половина
 * правил которой не разобрана или увешана открытыми замечаниями, стоит
 * меньше — и это должно быть видно там же, где принимают решение.
 */
export function RuleList({
  snapshotId,
  rules,
}: {
  snapshotId: number
  rules: AttackRuleBrief[]
}) {
  if (rules.length === 0) {
    return <p className="text-xs text-text-secondary">правил нет</p>
  }
  return (
    <ul className="flex flex-col gap-0.5">
      {rules.map((r) => {
        const level = attentionLevel(r.parse_status, r.open_finding_count, r.max_severity)
        return (
          <li key={r.uuid} className="flex items-center gap-2 rounded px-1 py-0.5 hover:bg-row-hover">
            <span className="min-w-0 flex-1 truncate" title={r.name}>
              <Link
                to={`/siem/snapshots/${snapshotId}/rules?q=${encodeURIComponent(r.name)}`}
                className="font-mono text-xs text-text hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
              >
                {r.name}
              </Link>
            </span>
            {r.scoped && (
              <span
                className="shrink-0 text-[11px] text-text-secondary"
                title="Правило ограничено табличным списком: детектирование не шире списка"
              >
                по списку
              </span>
            )}
            <AttentionBadge level={level} count={r.open_finding_count} className="shrink-0" />
          </li>
        )
      })}
    </ul>
  )
}
