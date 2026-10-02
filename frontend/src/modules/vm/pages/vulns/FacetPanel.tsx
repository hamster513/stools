import type { ReactNode } from 'react'
import type { CvssSource, RiskLevel, VulnsFacets, VulnsQuery } from '@/modules/vm/api/types'
import { CVSS_SOURCE_LABELS, LEVEL_LABELS, LEVELS } from '@/modules/vm/api/types'
import { LEVEL_TEXT } from '@/modules/vm/components/RiskBadge'
import { ASSIGNEE_SPECIAL, STATUS_OPTIONS, toggleStatus, type FindingFacetFilters } from '@/platform/findings/facets'
import { cn } from '@/lib/cn'

export type VulnFilters = Pick<VulnsQuery, 'level' | 'criticality' | 'zone' | 'os' | 'exploits' | 'msf' | 'cvss_source'> & FindingFacetFilters

const CRITICALITIES = ['Critical', 'High', 'Medium', 'Low', 'None', '']

function Row({ active, count, onClick, children }: { active: boolean; count: number | undefined; onClick: () => void; children: ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'flex w-full items-center justify-between gap-2 rounded px-2 py-1.5 text-left text-xs',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring',
        active ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text',
      )}
      aria-pressed={active}
    >
      <span className="min-w-0 flex-1 truncate">{children}</span>
      <span className="font-mono text-[11px] tabular-nums text-text-secondary">{(count ?? 0).toLocaleString('ru-RU')}</span>
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

interface Props {
  facets: VulnsFacets | undefined
  filters: VulnFilters
  onToggle: <K extends keyof VulnFilters>(key: K, value: VulnFilters[K]) => void
  total: number
  myLogin: string | undefined
  names: Map<string, string>
}

/**
 * Фасеты считаются на сервере по всей выборке — счётчики не плывут при прокрутке.
 * Статус пары — мультивыбор; пока ничего не выбрано, показываются открытые.
 * Счётчики статусов и исполнителей — без своего фильтра.
 */
export function FacetPanel({ facets, filters, onToggle, total, myLogin, names }: Props) {
  const zones = Object.entries(facets?.zone ?? {}).sort((a, b) => b[1] - a[1])
  const oses = Object.entries(facets?.os ?? {}).sort((a, b) => b[1] - a[1])
  const crits = CRITICALITIES.filter((c) => (facets?.criticality[c] ?? 0) > 0 || filters.criticality === c)
  const assignees = Object.entries(facets?.assignee ?? {}).filter(([login]) => login !== 'none' && login !== myLogin).sort((a, b) => b[1] - a[1])
  const pickAssignee = (value: string) => onToggle('assignee', filters.assignee === value ? undefined : value)

  return (
    <div className="flex h-full w-64 shrink-0 flex-col overflow-y-auto border-r border-grid bg-surface">
      <div className="border-b border-grid px-4 py-3 text-xs text-text-secondary">
        Пар хост–CVE <span className="font-mono tabular-nums text-text">{total.toLocaleString('ru-RU')}</span>
      </div>

      <Section title="Статус" hint={filters.status ? undefined : filters.risk_expiring ? 'не выбран — показан принятый риск: среди открытых срока риска нет' : 'не выбран — показаны открытые: новая, в работе, исправлено, переоткрыта'}>
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

      <Section title="Риск">
        {LEVELS.map((l: RiskLevel) => (
          <Row key={l} active={filters.level === l} count={facets?.level[l]} onClick={() => onToggle('level', filters.level === l ? undefined : l)}>
            <span className={LEVEL_TEXT[l]}>{LEVEL_LABELS[l]}</span>
          </Row>
        ))}
      </Section>

      <Section title="Критичность хоста">
        {crits.map((c) => (
          <Row key={c || 'empty'} active={filters.criticality === c} count={facets?.criticality[c]} onClick={() => onToggle('criticality', filters.criticality === c ? undefined : c)}>
            {c || <span className="italic">не задана</span>}
          </Row>
        ))}
      </Section>

      <Section title="Зона">
        {zones.map(([z, n]) => (
          <Row key={z || 'empty'} active={filters.zone === z} count={n} onClick={() => onToggle('zone', filters.zone === z ? undefined : z)}>
            {z || <span className="italic">без зоны</span>}
          </Row>
        ))}
      </Section>

      <Section title="Эксплуатируемость">
        <Row active={filters.exploits === true} count={facets?.exploits.yes} onClick={() => onToggle('exploits', filters.exploits === true ? undefined : true)}>
          есть эксплойт в ExploitDB
        </Row>
        <Row active={filters.msf === true} count={facets?.msf.yes} onClick={() => onToggle('msf', filters.msf === true ? undefined : true)}>
          есть модуль Metasploit
        </Row>
      </Section>

      <Section title="Источник CVSS">
        {(Object.keys(CVSS_SOURCE_LABELS) as CvssSource[]).map((s) => (
          <Row key={s} active={filters.cvss_source === s} count={facets?.cvss_source[s]} onClick={() => onToggle('cvss_source', filters.cvss_source === s ? undefined : s)}>
            {CVSS_SOURCE_LABELS[s]}
          </Row>
        ))}
      </Section>

      <Section title="ОС">
        {oses.map(([os, n]) => (
          <Row key={os || 'empty'} active={filters.os === os} count={n} onClick={() => onToggle('os', filters.os === os ? undefined : os)}>
            {os || <span className="italic">не определена</span>}
          </Row>
        ))}
      </Section>
    </div>
  )
}
