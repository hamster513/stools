import type { ReactNode } from 'react'
import type { CvssSource, RiskLevel, VulnsFacets, VulnsQuery } from '@/modules/vm/api/types'
import { CVSS_SOURCE_LABELS, LEVEL_LABELS, LEVELS } from '@/modules/vm/api/types'
import { LEVEL_TEXT } from '@/modules/vm/components/RiskBadge'
import { ASSIGNEE_SPECIAL, STATUS_OPTIONS, statusForFlag, toggleStatus, toggleValue, type FindingFacetFilters } from '@/platform/findings/facets'
import type { FacetValue } from '@/platform/filters/useRememberedFacets'
import { cn } from '@/lib/cn'

export type VulnFilters = Pick<VulnsQuery, 'level' | 'criticality' | 'zone' | 'os' | 'exploits' | 'msf' | 'kev' | 'cvss_source'> & FindingFacetFilters

const CRITICALITIES = ['Critical', 'High', 'Medium', 'Low', 'None', '']

const has = (list: readonly string[] | undefined, value: string) => list?.includes(value) ?? false

function Row({ active, count, onClick, children }: { active: boolean; count: number | undefined; onClick: () => void; children: ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'flex w-full items-center justify-between gap-2 rounded px-2 py-1.5 text-left text-xs',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring',
        active ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text',
        // Значение, ушедшее в ноль под другими фильтрами, приглушено, но выбирается.
        !active && count === 0 && 'opacity-60',
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
  remembered: Partial<Record<'zone' | 'os' | 'assignee' | 'criticality', FacetValue[]>>
  filters: VulnFilters
  onToggle: <K extends keyof VulnFilters>(key: K, value: VulnFilters[K]) => void
  total: number
  myLogin: string | undefined
  names: Map<string, string>
}

/**
 * Фасеты считаются на сервере по всей выборке — счётчики не плывут при прокрутке.
 * Каждый фасет — мультивыбор («ИЛИ» внутри, «И» между фасетами); пока статус не
 * выбран, показываются открытые. Счётчики статусов и исполнителей — без своего
 * фильтра, остальные — по отфильтрованному набору: ушедшие в ноль значения
 * панель помнит: `remembered` считает страница (useRememberedFacets), чтобы
 * память жила, пока панель закрыта.
 */
export function FacetPanel({ facets, remembered, filters, onToggle, total, myLogin, names }: Props) {
  const zones = remembered.zone ?? []
  const oses = remembered.os ?? []
  // Критичности — в своём порядке; показываются виденные хоть раз и выбранные.
  const seenCrits = new Set((remembered.criticality ?? []).map((c) => c.value))
  const crits = CRITICALITIES.filter((c) => seenCrits.has(c) || has(filters.criticality, c))
  const assignees = (remembered.assignee ?? []).filter((a) => a.value !== 'none' && a.value !== myLogin)
  const pick = <K extends 'level' | 'criticality' | 'zone' | 'os' | 'cvss_source' | 'assignee'>(key: K, value: string) =>
    onToggle(key, toggleValue(filters[key] as string[] | undefined, value) as VulnFilters[K])

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

      <Section title="Риск">
        {LEVELS.map((l: RiskLevel) => (
          <Row key={l} active={has(filters.level, l)} count={facets?.level[l]} onClick={() => pick('level', l)}>
            <span className={LEVEL_TEXT[l]}>{LEVEL_LABELS[l]}</span>
          </Row>
        ))}
      </Section>

      <Section title="Критичность хоста">
        {crits.map((c) => (
          <Row key={c || 'empty'} active={has(filters.criticality, c)} count={facets?.criticality[c]} onClick={() => pick('criticality', c)}>
            {c || <span className="italic">не задана</span>}
          </Row>
        ))}
      </Section>

      <Section title="Зона">
        {zones.map(({ value: z, count }) => (
          <Row key={z || 'empty'} active={has(filters.zone, z)} count={count} onClick={() => pick('zone', z)}>
            {z || <span className="italic">без зоны</span>}
          </Row>
        ))}
      </Section>

      <Section title="Эксплуатируемость">
        <Row active={filters.kev === true} count={facets?.kev.yes} onClick={() => onToggle('kev', filters.kev === true ? undefined : true)}>
          в каталоге CISA KEV
        </Row>
        <Row active={filters.exploits === true} count={facets?.exploits.yes} onClick={() => onToggle('exploits', filters.exploits === true ? undefined : true)}>
          есть эксплойт в ExploitDB
        </Row>
        <Row active={filters.msf === true} count={facets?.msf.yes} onClick={() => onToggle('msf', filters.msf === true ? undefined : true)}>
          есть модуль Metasploit
        </Row>
      </Section>

      <Section title="Источник CVSS">
        {(Object.keys(CVSS_SOURCE_LABELS) as CvssSource[]).map((s) => (
          <Row key={s} active={has(filters.cvss_source, s)} count={facets?.cvss_source[s]} onClick={() => pick('cvss_source', s)}>
            {CVSS_SOURCE_LABELS[s]}
          </Row>
        ))}
      </Section>

      <Section title="ОС">
        {oses.map(({ value: os, count }) => (
          <Row key={os || 'empty'} active={has(filters.os, os)} count={count} onClick={() => pick('os', os)}>
            {os || <span className="italic">не определена</span>}
          </Row>
        ))}
      </Section>
    </div>
  )
}
