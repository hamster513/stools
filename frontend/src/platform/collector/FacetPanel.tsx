import type { ReactNode } from 'react'
import { SEVERITIES, SEVERITY_LABELS, SEVERITY_TEXT, STATUS_LABELS, type FindingBase, type FindingFilters, type FindingsResponse, type FindingStatus } from './types'
import { cn } from '@/lib/cn'

function Row({ active, count, onClick, children }: { active: boolean; count: number | undefined; onClick: () => void; children: ReactNode }) {
  return (
    <button type="button" onClick={onClick} aria-pressed={active} className={cn('flex w-full items-center justify-between gap-2 rounded px-2 py-1.5 text-left text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring', active ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text')}>
      <span className="min-w-0 flex-1 truncate">{children}</span>
      <span className="font-mono text-[11px] tabular-nums text-text-secondary">{count ?? 0}</span>
    </button>
  )
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="border-b border-grid px-2 py-3">
      <div className="mb-1.5 px-2 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">{title}</div>
      <div className="flex flex-col gap-0.5">{children}</div>
    </div>
  )
}

const STATUSES: FindingStatus[] = ['new', 'persisting', 'accepted', 'fixed']

export function FacetPanel({ facets, titles, filters, onToggle, total }: { facets: FindingsResponse<FindingBase>['facets']; titles: Record<string, string>; filters: FindingFilters; onToggle: <K extends keyof FindingFilters>(key: K, value: FindingFilters[K]) => void; total: number }) {
  const checks = Object.entries(facets?.check ?? {}).sort((a, b) => b[1] - a[1])
  return (
    <div className="flex h-full w-64 shrink-0 flex-col overflow-y-auto border-r border-grid bg-surface">
      <div className="border-b border-grid px-4 py-3 text-xs text-text-secondary">Находок <span className="font-mono tabular-nums text-text">{total}</span></div>
      <Section title="Severity">
        {SEVERITIES.map((s) => (
          <Row key={s} active={filters.severity === s} count={facets?.severity[s]} onClick={() => onToggle('severity', filters.severity === s ? undefined : s)}><span className={SEVERITY_TEXT[s]}>{SEVERITY_LABELS[s]}</span></Row>
        ))}
      </Section>
      <Section title="Статус">
        {STATUSES.map((s) => (
          <Row key={s} active={filters.status === s} count={facets?.status[s]} onClick={() => onToggle('status', filters.status === s ? undefined : s)}>{STATUS_LABELS[s]}</Row>
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
