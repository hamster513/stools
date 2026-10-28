import type { ImageLevel, ImagesFacets, ImagesQuery, ImageScanStatus } from '@/modules/vm/api/types'
import { IMAGE_LEVEL_LABELS, IMAGE_LEVELS, SCAN_STATUS_LABELS, SCAN_STATUSES } from '@/modules/vm/api/types'
import { LEVEL_TEXT } from '@/modules/vm/components/RiskBadge'
import { toggleValue } from '@/platform/findings/facets'
import type { FacetValue } from '@/platform/filters/useRememberedFacets'
import { Row, Section } from '../vulns/FacetPanel'

export type ImageFilters = Pick<ImagesQuery, 'project' | 'scan_status' | 'level' | 'trivy'>

const has = (list: readonly string[] | undefined, value: string) => list?.includes(value) ?? false

interface Props {
  facets: ImagesFacets | undefined
  remembered: Partial<Record<'project' | 'scan_status', FacetValue[]>>
  filters: ImageFilters
  onToggle: <K extends keyof ImageFilters>(key: K, value: ImageFilters[K]) => void
  total: number
}

/**
 * Фасеты образов: проект, статус скана, уровень риска. Счётчики — по всей выборке
 * с фильтрами (сервер), ушедшие в ноль значения помнит страница (useRememberedFacets).
 */
export function ImagesFacetPanel({ facets, remembered, filters, onToggle, total }: Props) {
  const projects = remembered.project ?? []
  // Статусы — в своём порядке; показываются виденные хоть раз и выбранные.
  const seen = new Set((remembered.scan_status ?? []).map((s) => s.value))
  const statuses = SCAN_STATUSES.filter((s) => seen.has(s) || has(filters.scan_status, s))
  const pick = <K extends 'project' | 'scan_status' | 'level'>(key: K, value: string) =>
    onToggle(key, toggleValue(filters[key] as string[] | undefined, value) as ImageFilters[K])

  return (
    <div className="flex h-full w-64 shrink-0 flex-col overflow-y-auto border-r border-grid bg-surface">
      <div className="border-b border-grid px-4 py-3 text-xs text-text-secondary">
        Образов <span className="font-mono tabular-nums text-text">{total.toLocaleString('ru-RU')}</span>
      </div>

      <Section title="Проект Harbor">
        {projects.map(({ value: p, count }) => (
          <Row key={p} active={has(filters.project, p)} count={count} onClick={() => pick('project', p)}>
            <span className="font-mono">{p}</span>
          </Row>
        ))}
      </Section>

      <Section title="Статус скана">
        {statuses.map((s: ImageScanStatus) => (
          <Row key={s} active={has(filters.scan_status, s)} count={facets?.scan_status[s] ?? 0} onClick={() => pick('scan_status', s)}>
            {SCAN_STATUS_LABELS[s]}
          </Row>
        ))}
      </Section>

      <Section title="Риск" hint="наибольший среди находок образа">
        {IMAGE_LEVELS.map((l: ImageLevel) => (
          <Row key={l} active={has(filters.level, l)} count={facets?.level[l]} onClick={() => pick('level', l)}>
            {l === 'none' ? <span className="italic">{IMAGE_LEVEL_LABELS[l]}</span> : <span className={LEVEL_TEXT[l]}>{IMAGE_LEVEL_LABELS[l]}</span>}
          </Row>
        ))}
      </Section>
    </div>
  )
}
