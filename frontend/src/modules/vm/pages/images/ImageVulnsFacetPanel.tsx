import type { ImageLevel, ImageVulnsFacets, ImageVulnsQuery, TrivySeverity } from '@/modules/vm/api/types'
import { IMAGE_LEVEL_LABELS, IMAGE_LEVELS, TRIVY_SEVERITIES } from '@/modules/vm/api/types'
import { LEVEL_TEXT } from '@/modules/vm/components/RiskBadge'
import { toggleValue } from '@/platform/findings/facets'
import { Row, Section } from '../vulns/FacetPanel'
import { TrivyBadge } from './ImageVulnsTable'

export type ImageVulnFilters = Pick<ImageVulnsQuery, 'severity' | 'level' | 'fixed'>

const has = (list: readonly string[] | undefined, value: string) => list?.includes(value) ?? false

interface Props {
  facets: ImageVulnsFacets | undefined
  filters: ImageVulnFilters
  onToggle: <K extends keyof ImageVulnFilters>(key: K, value: ImageVulnFilters[K]) => void
  total: number
}

/**
 * Фасеты находок образа: оценка Trivy, уровень риска, наличие исправления. Счётчики — по всей
 * выборке (сервер): значения перечислены целиком, ушедшие в ноль приглушены, но выбираются.
 */
export function ImageVulnsFacetPanel({ facets, filters, onToggle, total }: Props) {
  const pick = <K extends 'severity' | 'level'>(key: K, value: string) =>
    onToggle(key, toggleValue(filters[key] as string[] | undefined, value) as ImageVulnFilters[K])
  const pickFixed = (value: 'yes' | 'no') => onToggle('fixed', filters.fixed === value ? undefined : value)

  return (
    <div className="flex h-full w-64 shrink-0 flex-col overflow-y-auto border-r border-grid bg-surface">
      <div className="border-b border-grid px-4 py-3 text-xs text-text-secondary">
        Находок <span className="font-mono tabular-nums text-text">{total.toLocaleString('ru-RU')}</span>
      </div>

      <Section title="Оценка Trivy">
        {TRIVY_SEVERITIES.map((s: TrivySeverity) => (
          <Row key={s} active={has(filters.severity, s)} count={facets?.severity[s] ?? 0} onClick={() => pick('severity', s)}>
            <TrivyBadge severity={s} />
          </Row>
        ))}
      </Section>

      <Section title="Уровень риска">
        {IMAGE_LEVELS.map((l: ImageLevel) => (
          <Row key={l} active={has(filters.level, l)} count={facets?.level[l] ?? 0} onClick={() => pick('level', l)}>
            {l === 'none' ? <span className="italic">{IMAGE_LEVEL_LABELS[l]}</span> : <span className={LEVEL_TEXT[l]}>{IMAGE_LEVEL_LABELS[l]}</span>}
          </Row>
        ))}
      </Section>

      <Section title="Исправление">
        <Row active={filters.fixed === 'yes'} count={facets?.fixed.yes ?? 0} onClick={() => pickFixed('yes')}>Есть исправленная версия</Row>
        <Row active={filters.fixed === 'no'} count={facets?.fixed.no ?? 0} onClick={() => pickFixed('no')}>Исправления нет</Row>
      </Section>
    </div>
  )
}
