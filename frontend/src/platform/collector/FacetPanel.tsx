import type { ReactNode } from 'react'
import { ASSIGNEE_SPECIAL, STATUS_OPTIONS, toggleStatus } from '@/platform/findings/facets'
import { SEVERITIES, SEVERITY_LABELS, SEVERITY_TEXT, type FindingBase, type FindingFilters, type FindingsResponse } from './types'
import { cn } from '@/lib/cn'

function Row({ active, count, onClick, children }: { active: boolean; count: number | undefined; onClick: () => void; children: ReactNode }) {
  return (
    <button type="button" onClick={onClick} aria-pressed={active} className={cn('flex w-full items-center justify-between gap-2 rounded px-2 py-1.5 text-left text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring', active ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text')}>
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
 * Фасеты находок модуля-сборщика. Статус — мультивыбор; пока ничего не
 * выбрано, сервер показывает открытые. Счётчики статусов и исполнителей
 * считаются без своего фильтра.
 */
export function FacetPanel({ facets, titles, filters, onToggle, total, myLogin, names }: {
  facets: FindingsResponse<FindingBase>['facets']
  titles: Record<string, string>
  filters: FindingFilters
  onToggle: <K extends keyof FindingFilters>(key: K, value: FindingFilters[K]) => void
  total: number
  myLogin: string | undefined
  names: Map<string, string>
}) {
  const checks = Object.entries(facets?.check ?? {}).sort((a, b) => b[1] - a[1])
  const assignees = Object.entries(facets?.assignee ?? {}).filter(([login]) => login !== 'none' && login !== myLogin).sort((a, b) => b[1] - a[1])
  const pickAssignee = (value: string) => onToggle('assignee', filters.assignee === value ? undefined : value)
  return (
    <div className="flex h-full w-64 shrink-0 flex-col overflow-y-auto border-r border-grid bg-surface">
      <div className="border-b border-grid px-4 py-3 text-xs text-text-secondary">Находок <span className="font-mono tabular-nums text-text">{total}</span></div>
      <Section title="Статус" hint={filters.status ? undefined : 'не выбран — показаны открытые: новая, в работе, исправлено, переоткрыта'}>
        {STATUS_OPTIONS.map(({ value, label }) => (
          <Row key={value} active={filters.status ? filters.status.includes(value) : false} count={facets?.status[value]} onClick={() => onToggle('status', toggleStatus(filters.status, value))}>
            {label}
          </Row>
        ))}
      </Section>
      <Section title="Исполнитель">
        <Row active={filters.assignee === 'me'} count={myLogin ? facets?.assignee[myLogin] : undefined} onClick={() => pickAssignee('me')}>{ASSIGNEE_SPECIAL.me}</Row>
        <Row active={filters.assignee === 'none'} count={facets?.assignee.none} onClick={() => pickAssignee('none')}>{ASSIGNEE_SPECIAL.none}</Row>
        {assignees.map(([login, n]) => (
          <Row key={login} active={filters.assignee === login} count={n} onClick={() => pickAssignee(login)}>{names.get(login) ?? login}</Row>
        ))}
      </Section>
      <Section title="Сроки">
        <Row active={filters.overdue === true} count={facets?.flags.overdue} onClick={() => onToggle('overdue', filters.overdue ? undefined : true)}>просроченные</Row>
        <Row active={filters.risk_expiring === true} count={facets?.flags.risk_expiring} onClick={() => onToggle('risk_expiring', filters.risk_expiring ? undefined : true)}>риск истекает (≤ 30 дней)</Row>
      </Section>
      <Section title="Снапшот">
        <Row active={filters.delta === 'new'} count={facets?.delta.new} onClick={() => onToggle('delta', filters.delta === 'new' ? undefined : 'new')}>появились в этом снапшоте</Row>
      </Section>
      <Section title="Severity">
        {SEVERITIES.map((s) => (
          <Row key={s} active={filters.severity === s} count={facets?.severity[s]} onClick={() => onToggle('severity', filters.severity === s ? undefined : s)}><span className={SEVERITY_TEXT[s]}>{SEVERITY_LABELS[s]}</span></Row>
        ))}
      </Section>
      <Section title="Allowlist">
        <Row active={filters.allowlisted === true} count={facets?.allowlisted.yes} onClick={() => onToggle('allowlisted', filters.allowlisted === true ? undefined : true)}>в allowlist (понижено до Low)</Row>
        <Row active={filters.allowlisted === false} count={facets?.allowlisted.no} onClick={() => onToggle('allowlisted', filters.allowlisted === false ? undefined : false)}>не в allowlist</Row>
      </Section>
      <Section title="Проверка">
        {checks.map(([code, n]) => (
          <Row key={code} active={filters.check === code} count={n} onClick={() => onToggle('check', filters.check === code ? undefined : code)}>{titles[code] ?? code}</Row>
        ))}
      </Section>
    </div>
  )
}
