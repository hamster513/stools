import type { ReactNode } from 'react'
import { ExternalLink, ShieldCheck } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { usePolicyFindings } from '@/modules/ksc/api/queries'
import { EXCLUSION_KIND_LABELS, EXCLUSION_RISKS, type PolicyCard, type PolicyGradeFinding } from '@/modules/ksc/api/types'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { SeverityBadge } from '@/platform/collector/SeverityBadge'
import { StatusBadge } from '@/platform/findings/StatusBadge'
import { Link } from '@/lib/router'
import { cn } from '@/lib/cn'
import { PartialNote } from '../objects/ObjectsParts'
import { GradeBadge } from '../policies/GradeBadge'

/** Ключи деталей, которые уже видны в карточке (политика, продукт, группа) и в строке находки не повторяются. */
const CONTEXT_KEYS = new Set(['policy_id', 'product', 'group'])

const str = (v: unknown): string => (typeof v === 'string' ? v : v === null || v === undefined ? '' : String(v))
const strList = (v: unknown): string[] => (Array.isArray(v) ? v.map(str).filter(Boolean) : [])
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null)

/** Список подписей с заголовком; пусто — ничего (null, чтобы строка деталей не появлялась). */
function items(key: string, label: string, titles: string[]): ReactNode {
  if (titles.length === 0) return null
  return (
    <div key={key}>
      <span className="text-text-secondary">{label}:</span>
      <ul className="ml-4 list-disc">
        {titles.map((t, i) => <li key={i}>{t}</li>)}
      </ul>
    </div>
  )
}

/** Подписи из `titles`, а без них — коды из `codes`. */
const titlesOr = (titles: unknown, codes: unknown): string[] => (strList(titles).length ? strList(titles) : strList(codes))

/**
 * Детали находки человеческим языком по виду проверки; использованные ключи — в `used`, остальные (кроме ключей контекста)
 * показываются как есть. Нет ключа или не тот вид — строки нет, без падения.
 */
function knownDetails(check: string, d: Record<string, unknown>): { body: ReactNode[]; used: string[] } {
  switch (check) {
    case 'POLICY_COMPONENT_OFF':
    case 'POLICY_NOTIFY_ONLY':
      return { body: [str(d.title || d.component) && <div key="c"><span className="text-text-secondary">Компонент:</span> {str(d.title || d.component)}</div>], used: ['title', 'component'] }
    case 'POLICY_THREAT_TYPES_OFF':
      return { body: [items('t', 'Не обнаруживаются', titlesOr(d.titles, d.types))], used: ['titles', 'types'] }
    case 'POLICY_LOCAL_EXCLUSIONS':
      return { body: [items('t', 'Разрешено на компьютере', titlesOr(d.titles, d.allowed))], used: ['titles', 'allowed'] }
    case 'POLICY_KEY_UNLOCKED':
      return { body: [items('t', 'Не под замком', titlesOr(d.titles, d.unlocked))], used: ['titles', 'unlocked'] }
    case 'POLICY_NO_LOCKS':
    case 'POLICY_WEAK_LOCKS': {
      const locked = num(d.locked)
      const flagged = num(d.with_lock_flag)
      const share = num(d.share)
      const text = locked !== null && flagged !== null ? `замкнуто ${locked} из ${flagged}${share !== null ? ` (${Math.round(share * 100)}%)` : ''}` : ''
      return { body: [text && <div key="l"><span className="text-text-secondary">Замки:</span> {text}</div>], used: ['locked', 'with_lock_flag', 'share', 'total'] }
    }
    case 'POLICY_EXCLUSION_RISKY': {
      const kind = str(d.kind)
      return {
        body: [
          <div key="v">
            <span className="text-text-secondary">{kind ? `${EXCLUSION_KIND_LABELS[kind] ?? kind}:` : 'Исключение:'}</span> <span className="font-mono break-all">{str(d.value) || '—'}</span>
            <span className="text-text-secondary"> · {str(d.profile) ? `профиль ${str(d.profile)}` : 'сама политика'}</span>
          </div>,
          items('w', 'Почему опасно', strList(d.why).length ? strList(d.why) : strList(d.risks).map((c) => EXCLUSION_RISKS[c]?.label ?? c)),
          str(d.comment) && <div key="k"><span className="text-text-secondary">Комментарий:</span> {str(d.comment)}</div>,
        ],
        used: ['kind', 'value', 'profile', 'why', 'risks', 'comment'],
      }
    }
    default:
      return { body: [], used: [] }
  }
}

function Details({ finding }: { finding: PolicyGradeFinding }) {
  const d = finding.details ?? {}
  const { body, used } = knownDetails(finding.check, d)
  const rest = Object.entries(d).filter(([k, v]) => !CONTEXT_KEYS.has(k) && !used.includes(k) && v !== null && v !== '' && !(Array.isArray(v) && v.length === 0))
  if (body.every((b) => !b) && rest.length === 0) return null
  return (
    <div className="mt-1 flex flex-col gap-0.5 text-xs text-text">
      {body}
      {rest.map(([k, v]) => (
        <div key={k}><span className="font-mono text-text-secondary">{k}:</span> <span className="font-mono break-all">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span></div>
      ))}
    </div>
  )
}

function FindingRow({ finding, serverId, policyName }: { finding: PolicyGradeFinding; serverId: number; policyName: string }) {
  const link = `/ksc/servers/${serverId}/findings?check=${encodeURIComponent(finding.check)}&q=${encodeURIComponent(policyName)}&key=${encodeURIComponent(finding.key)}`
  return (
    <li className={cn('border-t border-grid px-3 py-2.5', !finding.counted && 'opacity-70')}>
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={finding.severity} />
        <span className="text-xs font-medium text-text" title={finding.check}>{finding.check_title}</span>
        <StatusBadge status={finding.status} />
        {!finding.counted && <span className="text-[11px] text-text-secondary" title="статус находки не входит в учитываемые: на оценку не влияет">не учитывается</span>}
        <Link to={link} className="ml-auto flex items-center gap-1 text-xs text-primary hover:underline">
          в «Находках» <ExternalLink size={11} aria-hidden />
        </Link>
      </div>
      <Details finding={finding} />
    </li>
  )
}

/** Вкладка «Оценка»: оценка политики крупно с причиной и находки оценки — считаемые первыми, несчитаемые с пометкой. */
export function GradeTab({ serverId, snapshotId, policy }: { serverId: number; snapshotId: number; policy: PolicyCard }) {
  const findings = usePolicyFindings(snapshotId, policy.id)

  const header = (
    <>
      <div className="mb-4 flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <GradeBadge grade={policy.grade} reason={policy.grade_reason} large />
        <span className="text-xs text-text-secondary">{policy.grade_reason}</span>
      </div>
      {policy.contents_partial && <PartialNote />}
    </>
  )

  if (findings.isLoading) return <>{header}<FullPageSpinner /></>
  if (findings.isError || !findings.data) {
    const msg = findings.error instanceof ApiRequestError ? findings.error.message : 'Не удалось загрузить находки политики'
    return <>{header}<ErrorState message={msg} onRetry={() => findings.refetch()} /></>
  }
  const items = findings.data.items
  const counted = items.filter((f) => f.counted).length

  return (
    <>
      {header}
      {items.length === 0 ? (
        <EmptyState
          icon={ShieldCheck}
          title="Находок оценки нет"
          description={policy.grade === null ? 'Правила оценки по этой политике находок не дали; оценки нет по причине выше.' : 'Правила оценки по этой политике находок не дали.'}
        />
      ) : (
        <section className="rounded border border-grid bg-surface">
          <h2 className="px-3 py-2 text-xs font-semibold text-text">
            Находки оценки <span className="font-normal text-text-secondary">— учитываются {counted} из {items.length}</span>
          </h2>
          <ul>
            {items.map((f) => <FindingRow key={f.key} finding={f} serverId={serverId} policyName={policy.name} />)}
          </ul>
        </section>
      )}
    </>
  )
}
