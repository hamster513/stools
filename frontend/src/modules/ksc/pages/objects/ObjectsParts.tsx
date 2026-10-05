import type { ReactNode } from 'react'
import { FileQuestion, FilterX, ShieldQuestion } from 'lucide-react'
import { usePolicy, usePolicyList, useServers } from '@/modules/ksc/api/queries'
import { EXCLUSION_RISKS, type Severity } from '@/modules/ksc/api/types'
import { EmptyState } from '@/components/ui/EmptyState'
import { FullPageSpinner, Spinner } from '@/components/ui/Spinner'
import { cn } from '@/lib/cn'
import { FacetRow, FacetSection } from '../policies/Facets'

/** Раздел сервера, которому нужен последний снапшот: заголовок с номером снапшота и содержимое. */
export function SnapshotSection({ serverId, title, children }: { serverId: number; title: string; children: (snapshotId: number) => ReactNode }) {
  const servers = useServers()
  const snapshotId = servers.data?.find((s) => s.id === serverId)?.last_snapshot_id ?? undefined
  if (servers.isLoading) return <FullPageSpinner />
  if (snapshotId === undefined) {
    return <div className="p-6"><EmptyState icon={ShieldQuestion} title="Снапшотов нет" description="Загрузите выгрузку или запустите сбор из KSC в настройках модуля." /></div>
  }
  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex shrink-0 items-baseline gap-3 border-b border-grid bg-surface px-4 py-2.5">
        <h1 className="text-sm font-semibold text-text">{title}</h1>
        <span className="font-mono text-xs text-text-secondary">снапшот #{snapshotId}</span>
      </header>
      <div className="min-h-0 flex-1">{children(snapshotId)}</div>
    </div>
  )
}

/**
 * Фасет «Политика»: имена — из списка политик снапшота. С `counts` — только политики с записями и их число,
 * без `counts` — все политики снапшота без счётчика (у журнала изменений фасета по политике нет).
 */
export function PolicyFacet({ snapshotId, counts, selected, onSelect }: {
  snapshotId: number | undefined
  counts?: Record<string, number>
  selected: number | undefined
  onSelect: (policy: { id: number; name: string } | undefined) => void
}) {
  const list = usePolicyList(snapshotId, {})
  const names = new Map((list.data?.items ?? []).map((p) => [p.id, p.name]))
  const rows = counts
    ? Object.entries(counts).map(([id, n]) => ({ id: Number(id), name: names.get(Number(id)) ?? `#${id}`, n }))
    : (list.data?.items ?? []).map((p) => ({ id: p.id, name: p.name, n: undefined }))
  rows.sort((a, b) => a.name.localeCompare(b.name, 'ru'))
  return (
    <FacetSection title="Политика">
      {rows.map((r) => (
        <FacetRow key={r.id} active={selected === r.id} count={r.n} onClick={() => onSelect(selected === r.id ? undefined : { id: r.id, name: r.name })}>{r.name}</FacetRow>
      ))}
      {rows.length === 0 && <span className="px-2 text-xs text-text-secondary">нет</span>}
    </FacetSection>
  )
}

/** Политика и профиль записи; в карточке политики — только профиль. */
export function PolicyCell({ policyName, profile, inPolicy }: { policyName: string; profile: string; inPolicy: boolean }) {
  return (
    <>
      {!inPolicy && <div className="truncate text-text" title={policyName}>{policyName || '—'}</div>}
      <div className="truncate text-text-secondary" title={profile}>{profile ? `профиль ${profile}` : 'сама политика'}</div>
    </>
  )
}

const RISK_CLASSES: Partial<Record<Severity, string>> = {
  Critical: 'border-risk-critical/60 bg-risk-critical/15 text-risk-critical',
  High: 'border-risk-high/60 bg-risk-high/15 text-risk-high',
  Medium: 'border-risk-medium/60 bg-risk-medium/15 text-risk-medium',
}
const SEVERITY_ORDER: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Info']

/**
 * Риски исключения короткими подписями; цвет строки — по старшей серьёзности её кодов, объяснения — во всплывающей подсказке.
 * Код, которого нет в подписях, показывается как есть (без цвета серьёзности).
 */
export function RiskChips({ risks, titles }: { risks: string[]; titles: string[] }) {
  if (risks.length === 0) return <span className="text-text-secondary">—</span>
  const top = SEVERITY_ORDER.find((sev) => risks.some((c) => EXCLUSION_RISKS[c]?.severity === sev))
  const classes = (top && RISK_CLASSES[top]) || 'border-grid text-text-secondary'
  return (
    <div className="flex flex-wrap gap-1" title={titles.join('\n')}>
      {risks.map((c) => (
        <span key={c} className={cn('inline-flex items-center rounded border px-1.5 py-0.5 text-[11px] font-medium whitespace-nowrap', classes)}>{EXCLUSION_RISKS[c]?.label ?? c}</span>
      ))}
    </div>
  )
}

/** Догрузка следующей страницы списка. */
export function LoadMore({ loaded, total, hasNext, fetching, onMore }: { loaded: number; total: number; hasNext: boolean; fetching: boolean; onMore: () => void }) {
  if (!hasNext) return null
  return (
    <div className="flex items-center gap-3 px-4 py-3 text-xs text-text-secondary">
      <button type="button" onClick={onMore} disabled={fetching} className="rounded border border-border px-2 py-1 text-text hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring disabled:opacity-50">
        Показать ещё
      </button>
      {fetching && <Spinner size={14} />}
      <span>загружено {loaded} из {total}</span>
    </div>
  )
}

/** Строка над непустым списком: продукты без описания структуры, чьи записи в списке не показаны. */
export function UndescribedNote({ codes, what }: { codes: string[]; what: string }) {
  if (codes.length === 0) return null
  return (
    <div className="border-b border-grid bg-surface px-4 py-2 text-xs text-text-secondary">
      Структура продукта не описана: <span className="font-mono text-text">{codes.join(', ')}</span> — {what} этих политик появятся после описания структуры.
    </div>
  )
}

/**
 * Пустой список: «не собрано» и «не описано» отличаются от «нет». В карточке политики решает сама политика
 * (`undescribed` снапшота относится ко всем продуктам), в разделе сервера — список политик и `undescribed` ответа.
 */
export function ObjectsEmpty({ snapshotId, policyId, undescribed, hasFilters, what, none, nothing }: {
  snapshotId: number
  policyId?: number
  undescribed: string[]
  hasFilters: boolean
  /** «исключения» / «сетевые правила». */
  what: string
  /** «Исключений нет». */
  none: string
  /** «Ни одно исключение не подходит под фильтры.» */
  nothing: string
}) {
  const policy = usePolicy(policyId === undefined ? undefined : snapshotId, policyId)
  // В разделе сервера `undescribed` не видит политик без содержимого: «не собрано» считается по списку политик (кэш общий с PolicyFacet).
  const list = usePolicyList(policyId === undefined ? snapshotId : undefined, {})
  const all = list.data?.items.length ?? 0
  const collected = list.data?.items.filter((p) => p.has_contents).length ?? 0
  const partial = policyId === undefined && collected > 0 && collected < all ? ` Содержимое собрано только у ${collected} из ${all} политик.` : ''
  // Пока не известно, собрано ли содержимое, «нет» не говорится: без ответа о политиках это была бы догадка.
  const source = policyId === undefined ? list : policy
  let body: ReactNode
  if (hasFilters) body = <EmptyState icon={FilterX} title="Ничего не найдено" description={nothing} />
  else if (source.isLoading) body = <div className="flex justify-center py-16"><Spinner /></div>
  else if (source.isError) {
    body = (
      <EmptyState icon={FileQuestion} title={policyId === undefined ? 'Не удалось загрузить список политик' : 'Не удалось загрузить политику'} description={`Неизвестно, собраны ли ${what}: обновите страницу.`} />
    )
  } else if (policyId === undefined && all > 0 && collected === 0) {
    body = (
      <EmptyState icon={FileQuestion} title="Содержимое политик не собрано" description={`Без содержимого политик ${what} не извлекаются; это не значит, что их нет. Соберите выгрузку с содержимым политик — скрипт сбора без ключа -SkipPolicyContents.`} />
    )
  } else if (policyId !== undefined && policy.data && !policy.data.has_contents) {
    body = <EmptyState icon={FileQuestion} title="Содержимое политики не собрано" description={`Без содержимого политики ${what} не извлекаются. Соберите выгрузку с содержимым политик.`} />
  } else if (policyId !== undefined && policy.data && !policy.data.described) {
    body = <EmptyState icon={FileQuestion} title="Структура продукта не описана" description={`Продукт ${policy.data.product}: ${what} появятся после описания структуры продукта.`} />
  } else if (policyId === undefined && undescribed.length > 0) {
    body = <EmptyState icon={FileQuestion} title="Структура продукта не описана" description={`Продукты: ${undescribed.join(', ')}. Их ${what} появятся после описания структуры продукта; это не значит, что их нет.${partial}`} />
  } else body = <EmptyState icon={FilterX} title={none} description={`В собранном содержимом политик ${what} не найдены.${partial}`} />
  return <div className="p-6">{body}</div>
}
