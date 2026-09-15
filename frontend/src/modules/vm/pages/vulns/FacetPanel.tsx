import type { ReactNode } from 'react'
import type { CvssSource, RiskLevel, VulnsFacets, VulnsQuery } from '@/modules/vm/api/types'
import { CVSS_SOURCE_LABELS, LEVEL_LABELS, LEVELS } from '@/modules/vm/api/types'
import { LEVEL_TEXT } from '@/modules/vm/components/RiskBadge'
import { cn } from '@/lib/cn'

export type VulnFilters = Pick<VulnsQuery, 'level' | 'criticality' | 'zone' | 'os' | 'exploits' | 'msf' | 'cvss_source'>

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

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="border-b border-grid px-2 py-3">
      <div className="mb-1.5 px-2 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">{title}</div>
      <div className="flex flex-col gap-0.5">{children}</div>
    </div>
  )
}

interface Props {
  facets: VulnsFacets | undefined
  filters: VulnFilters
  onToggle: <K extends keyof VulnFilters>(key: K, value: VulnFilters[K]) => void
  total: number
}

/** Фасеты считаются на сервере по всей выборке — счётчики не плывут при прокрутке. */
export function FacetPanel({ facets, filters, onToggle, total }: Props) {
  const zones = Object.entries(facets?.zone ?? {}).sort((a, b) => b[1] - a[1])
  const oses = Object.entries(facets?.os ?? {}).sort((a, b) => b[1] - a[1])
  const crits = CRITICALITIES.filter((c) => (facets?.criticality[c] ?? 0) > 0 || filters.criticality === c)

  return (
    <div className="flex h-full w-64 shrink-0 flex-col overflow-y-auto border-r border-grid bg-surface">
      <div className="border-b border-grid px-4 py-3 text-xs text-text-secondary">
        Пар хост–CVE <span className="font-mono tabular-nums text-text">{total.toLocaleString('ru-RU')}</span>
      </div>

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
