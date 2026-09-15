import type { ReactNode } from 'react'
import type {
  FindingKind,
  FindingsFacets,
  FindingStatus,
  ObjectType,
  Polarity,
  ShapeFilter,
} from '@/modules/siem/api/types'
import { OBJECT_TYPE_LABELS, POLARITY_LABELS } from '@/modules/siem/api/types'
import { cn } from '@/lib/cn'
import { KindBadge } from '@/modules/siem/components/ui/KindBadge'
import { StatusBadge } from '@/modules/siem/components/ui/StatusBadge'

export interface HygieneFilters {
  kind?: FindingKind
  polarity?: Polarity
  object_type?: ObjectType
  in_table?: boolean
  shape?: ShapeFilter
  status?: FindingStatus
  field?: string
}

interface FacetPanelProps {
  facets: FindingsFacets | undefined
  fieldFacet: Record<string, number> | undefined
  filters: HygieneFilters
  onToggle: <K extends keyof HygieneFilters>(key: K, value: HygieneFilters[K]) => void
  total: number
}

function Row({
  active,
  count,
  onClick,
  children,
}: {
  active: boolean
  count: number | undefined
  onClick: () => void
  children: ReactNode
}) {
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
      <span className="tabular-nums font-mono text-[11px] text-text-secondary">{count ?? 0}</span>
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

const KINDS: FindingKind[] = ['1', '2', '3', '4', '5']
const OBJECT_TYPES: ObjectType[] = ['correlation', 'filter', 'enrichment']
//: Пустая форма — обычное значение: не адрес и не имя узла. Показывается
//: наравне с прочими: «сколько сетевых имён» имеет смысл только рядом
//: с «а сколько не сетевых».
const SHAPES = [
  { key: 'fqdn', label: 'имя узла' },
  { key: 'ip', label: 'IP-адрес' },
  { key: 'cidr', label: 'подсеть' },
  { key: 'plain', label: 'обычное значение' },
] as const

const POLARITIES: Polarity[] = ['negation', 'assertion']
const STATUSES: FindingStatus[] = ['open', 'in_progress', 'accepted']

export function FacetPanel({ facets, fieldFacet, filters, onToggle, total }: FacetPanelProps) {
  const topFields = Object.entries(fieldFacet ?? {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 12)

  return (
    <div className="flex h-full w-64 shrink-0 flex-col overflow-y-auto border-r border-grid bg-surface">
      <div className="border-b border-grid px-4 py-3">
        <div className="text-xs text-text-secondary">
          Всего находок <span className="font-mono tabular-nums text-text">{total}</span>
        </div>
      </div>

      <Section title="Класс">
        {KINDS.map((k) => (
          <Row key={k} active={filters.kind === k} count={facets?.kind[k]} onClick={() => onToggle('kind', filters.kind === k ? undefined : k)}>
            <span className="inline-flex items-center gap-1.5">
              <KindBadge kind={k} className="border-none bg-transparent px-0 py-0" />
            </span>
          </Row>
        ))}
      </Section>

      <Section title="Тип объекта">
        {OBJECT_TYPES.map((t) => (
          <Row
            key={t}
            active={filters.object_type === t}
            count={facets?.object_type[t]}
            onClick={() => onToggle('object_type', filters.object_type === t ? undefined : t)}
          >
            {OBJECT_TYPE_LABELS[t]}
          </Row>
        ))}
      </Section>

      <Section title="Полярность">
        {POLARITIES.map((p) => (
          <Row
            key={p}
            active={filters.polarity === p}
            count={facets?.polarity[p]}
            onClick={() => onToggle('polarity', filters.polarity === p ? undefined : p)}
          >
            {POLARITY_LABELS[p]}
          </Row>
        ))}
      </Section>

      {/* Форма значения — не то же, что класс. Классы взаимоисключающи,
          и «дублирует список» перекрывает «IP / CIDR / FQDN»: сетевое имя,
          лежащее в списке, в классе становится невидимым. На эталонной
          выгрузке таких имён 585, а в классе видно 371. */}
      <Section title="Форма значения">
        {SHAPES.map(({ key, label }) => (
          <Row
            key={key}
            active={filters.shape === key}
            count={facets?.shape[key]}
            onClick={() => onToggle('shape', filters.shape === key ? undefined : key)}
          >
            {label}
          </Row>
        ))}
      </Section>

      <Section title="В табличном списке">
        <Row active={filters.in_table === true} count={facets?.in_table.true} onClick={() => onToggle('in_table', filters.in_table === true ? undefined : true)}>
          Есть в списке
        </Row>
        <Row active={filters.in_table === false} count={facets?.in_table.false} onClick={() => onToggle('in_table', filters.in_table === false ? undefined : false)}>
          Нет в списке
        </Row>
      </Section>

      <Section title="Статус">
        {STATUSES.map((s) => (
          <Row key={s} active={filters.status === s} count={facets?.status[s]} onClick={() => onToggle('status', filters.status === s ? undefined : s)}>
            <StatusBadge status={s} className="border-none bg-transparent px-0 py-0" />
          </Row>
        ))}
      </Section>

      <Section title="Поле">
        {topFields.length === 0 && <div className="px-2 py-1 text-xs text-text-secondary">нет данных</div>}
        {topFields.map(([field, cnt]) => (
          <Row key={field} active={filters.field === field} count={cnt} onClick={() => onToggle('field', filters.field === field ? undefined : field)}>
            <span className="font-mono text-[11px]">{field}</span>
          </Row>
        ))}
      </Section>

      <div className="mt-auto px-2 py-1" />
    </div>
  )
}
