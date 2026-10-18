import type { ReactNode } from 'react'
import { ASSIGNEE_SPECIAL, STATUS_OPTIONS, statusForFlag, toggleStatus, toggleValue } from '@/platform/findings/facets'
import type { FacetValue } from '@/platform/filters/useRememberedFacets'
import { SEVERITIES, SEVERITY_LABELS, SEVERITY_TEXT, type FindingBase, type FindingDelta, type FindingFilters, type FindingsResponse } from './types'
import { cn } from '@/lib/cn'

/** Строка — переключатель значения в мультивыборе; значение, ушедшее в ноль, приглушено, но выбирается. */
function Row({ active, count, onClick, children }: { active: boolean; count: number | undefined; onClick: () => void; children: ReactNode }) {
  return (
    <button type="button" onClick={onClick} aria-pressed={active} className={cn('flex w-full items-center justify-between gap-2 rounded px-2 py-1.5 text-left text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring', active ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text', !active && count === 0 && 'opacity-60')}>
      <span className="min-w-0 flex-1 truncate">{children}</span>
      <span className="font-mono text-[11px] tabular-nums text-text-secondary">{count ?? 0}</span>
    </button>
  )
}

function Section({ title, hint, children }: { title: string; hint?: string; children: ReactNode }) {
  return (
    <div className="border-b border-grid px-2 py-3">
      <div className="mb-1.5 px-2 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">{title}</div>
      {hint && <div className="mb-1.5 px-2 text-[11px] text-text-secondary">{hint}</div>}
      <div className="flex flex-col gap-0.5">{children}</div>
    </div>
  )
}

/**
 * Фасеты находок модуля-сборщика. Каждый фасет — мультивыбор («ИЛИ» внутри,
 * «И» между фасетами); пока статус не выбран, сервер показывает открытые.
 * Счётчики статусов и исполнителей считаются без своего фильтра, остальные —
 * по отфильтрованному набору: проверки и исполнители, ушедшие в ноль, панель
 * помнит: `remembered` считает страница (useRememberedFacets), чтобы память
 * жила, пока панель закрыта.
 */
export function FacetPanel({ facets, remembered, titles, filters, onToggle, total, myLogin, names }: {
  facets: FindingsResponse<FindingBase>['facets']
  remembered: Partial<Record<'check' | 'assignee', FacetValue[]>>
  titles: Record<string, string>
  filters: FindingFilters
  onToggle: <K extends keyof FindingFilters>(key: K, value: FindingFilters[K]) => void
  total: number
  myLogin: string | undefined
  names: Map<string, string>
}) {
  const checks = remembered.check ?? []
  const assignees = (remembered.assignee ?? []).filter((a) => a.value !== 'none' && a.value !== myLogin)
  const pick = <K extends 'check' | 'severity' | 'delta' | 'assignee'>(key: K, value: string) =>
    onToggle(key, toggleValue(filters[key] as string[] | undefined, value) as FindingFilters[K])
  const has = (list: readonly string[] | undefined, value: string) => list?.includes(value) ?? false
  return (
    <div className="flex h-full w-64 shrink-0 flex-col overflow-y-auto border-r border-grid bg-surface">
      <div className="border-b border-grid px-4 py-3 text-xs text-text-secondary">Находок <span className="font-mono tabular-nums text-text">{total}</span></div>
      <Section title="Статус" hint={filters.status ? undefined : filters.risk_expiring ? 'не выбран — показан принятый риск: среди открытых срока риска нет' : 'не выбран — показаны открытые: новая, в работе, исправлено, переоткрыта'}>
        {STATUS_OPTIONS.map(({ value, label }) => (
          <Row key={value} active={filters.status ? filters.status.includes(value) : false} count={facets?.status[value]} onClick={() => onToggle('status', toggleStatus(filters.status, value))}>
            {label}
          </Row>
        ))}
      </Section>
      <Section title="Исполнитель">
        <Row active={has(filters.assignee, 'me')} count={myLogin ? facets?.assignee[myLogin] : undefined} onClick={() => pick('assignee', 'me')}>{ASSIGNEE_SPECIAL.me}</Row>
        <Row active={has(filters.assignee, 'none')} count={facets?.assignee.none} onClick={() => pick('assignee', 'none')}>{ASSIGNEE_SPECIAL.none}</Row>
        {assignees.map(({ value: login, count }) => (
          <Row key={login} active={has(filters.assignee, login)} count={count} onClick={() => pick('assignee', login)}>{names.get(login) ?? login}</Row>
        ))}
      </Section>
      <Section title="Сроки">
        <Row active={filters.overdue === true} count={facets?.flags.overdue} onClick={() => { if (!filters.overdue) onToggle('status', statusForFlag('overdue', filters.status)); onToggle('overdue', filters.overdue ? undefined : true) }}>просроченные</Row>
        <Row active={filters.risk_expiring === true} count={facets?.flags.risk_expiring} onClick={() => { if (!filters.risk_expiring) onToggle('status', statusForFlag('risk_expiring', filters.status)); onToggle('risk_expiring', filters.risk_expiring ? undefined : true) }}>риск истекает (≤ 30 дней)</Row>
      </Section>
      <Section title="Снапшот">
        {(['new', 'gone'] as FindingDelta[]).map((d) => (
          <Row key={d} active={has(filters.delta, d)} count={facets?.delta[d]} onClick={() => pick('delta', d)}>{d === 'new' ? 'появились в этом снапшоте' : 'исчезла (нет в последнем снапшоте)'}</Row>
        ))}
      </Section>
      <Section title="Severity">
        {SEVERITIES.map((s) => (
          <Row key={s} active={has(filters.severity, s)} count={facets?.severity[s]} onClick={() => pick('severity', s)}><span className={SEVERITY_TEXT[s]}>{SEVERITY_LABELS[s]}</span></Row>
        ))}
      </Section>
      <Section title="Allowlist">
        <Row active={filters.allowlisted === true} count={facets?.allowlisted.yes} onClick={() => onToggle('allowlisted', filters.allowlisted === true ? undefined : true)}>в allowlist (понижено до Low)</Row>
        <Row active={filters.allowlisted === false} count={facets?.allowlisted.no} onClick={() => onToggle('allowlisted', filters.allowlisted === false ? undefined : false)}>не в allowlist</Row>
      </Section>
      <Section title="Проверка">
        {checks.map(({ value: code, count }) => (
          <Row key={code} active={has(filters.check, code)} count={count} onClick={() => pick('check', code)}>{titles[code] ?? code}</Row>
        ))}
      </Section>
    </div>
  )
}
