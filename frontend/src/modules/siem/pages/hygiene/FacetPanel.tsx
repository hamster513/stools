import type { ReactNode } from 'react'
import type {
  FindingKind,
  FindingsFacets,
  ObjectType,
  Polarity,
  ShapeFilter,
} from '@/modules/siem/api/types'
import { OBJECT_TYPE_LABELS, POLARITY_LABELS, SHAPE_LABELS } from '@/modules/siem/api/types'
import { cn } from '@/lib/cn'
import { KindBadge } from '@/modules/siem/components/ui/KindBadge'
import { ASSIGNEE_SPECIAL, STATUS_OPTIONS, statusForFlag, toggleStatus, toggleValue, type FindingFacetFilters } from '@/platform/findings/facets'
import type { FacetValue } from '@/platform/filters/useRememberedFacets'

/** Статус, исполнитель и сроки — общие фасеты статусов находок платформы. Перечислимые фасеты — мультивыбор. */
export interface HygieneFilters extends FindingFacetFilters {
  kind?: FindingKind[]
  polarity?: Polarity[]
  object_type?: ObjectType[]
  in_table?: boolean
  shape?: ShapeFilter[]
  field?: string[]
}

type MultiKey = 'kind' | 'polarity' | 'object_type' | 'shape' | 'field' | 'assignee'

const has = (list: readonly string[] | undefined, value: string) => list?.includes(value) ?? false

interface FacetPanelProps {
  facets: FindingsFacets | undefined
  /** Поля и исполнители, которые панель уже показывала; считает страница (useRememberedFacets), чтобы память жила, пока панель закрыта. */
  remembered: Partial<Record<'field' | 'assignee', FacetValue[]>>
  filters: HygieneFilters
  onToggle: <K extends keyof HygieneFilters>(key: K, value: HygieneFilters[K]) => void
  total: number
  myLogin: string | undefined
  /** Логин → имя из справочника исполнителей. */
  names: Map<string, string>
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
        // Значение, ушедшее в ноль под другими фильтрами, приглушено, но выбирается.
        !active && count === 0 && 'opacity-60',
      )}
      aria-pressed={active}
    >
      <span className="min-w-0 flex-1 truncate">{children}</span>
      <span className="tabular-nums font-mono text-[11px] text-text-secondary">{count ?? 0}</span>
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

const KINDS: FindingKind[] = ['1', '2', '3', '4', '5']
const OBJECT_TYPES: ObjectType[] = ['correlation', 'filter', 'enrichment']
//: Пустая форма — обычное значение: не адрес и не имя узла. Показывается
//: наравне с прочими: «сколько сетевых имён» имеет смысл только рядом
//: с «а сколько не сетевых».
const SHAPES = [
  { key: 'fqdn', label: SHAPE_LABELS.fqdn },
  { key: 'ip', label: SHAPE_LABELS.ip },
  { key: 'cidr', label: SHAPE_LABELS.cidr },
  { key: 'plain', label: SHAPE_LABELS.plain },
] as const

const POLARITIES: Polarity[] = ['negation', 'assertion']

export function FacetPanel({ facets, remembered, filters, onToggle, total, myLogin, names }: FacetPanelProps) {
  // Счётчики считаются по отфильтрованному набору: поля и исполнители, ушедшие
  // в ноль, панель помнит, иначе второе значение было бы не выбрать.
  const topFields = remembered.field ?? []
  const assignees = (remembered.assignee ?? []).filter((a) => a.value !== 'none' && a.value !== myLogin)
  const pick = <K extends MultiKey>(key: K, value: string) =>
    onToggle(key, toggleValue(filters[key] as string[] | undefined, value) as HygieneFilters[K])

  return (
    <div className="flex h-full w-64 shrink-0 flex-col overflow-y-auto border-r border-grid bg-surface">
      <div className="border-b border-grid px-4 py-3">
        <div className="text-xs text-text-secondary">
          Всего находок <span className="font-mono tabular-nums text-text">{total}</span>
        </div>
      </div>

      <Section title="Статус" hint={filters.status ? undefined : 'не выбран — показаны открытые: новая, в работе, исправлено, переоткрыта'}>
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

      <Section title="Класс">
        {KINDS.map((k) => (
          <Row key={k} active={has(filters.kind, k)} count={facets?.kind[k]} onClick={() => pick('kind', k)}>
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
            active={has(filters.object_type, t)}
            count={facets?.object_type[t]}
            onClick={() => pick('object_type', t)}
          >
            {OBJECT_TYPE_LABELS[t]}
          </Row>
        ))}
      </Section>

      <Section title="Полярность">
        {POLARITIES.map((p) => (
          <Row
            key={p}
            active={has(filters.polarity, p)}
            count={facets?.polarity[p]}
            onClick={() => pick('polarity', p)}
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
            active={has(filters.shape, key)}
            count={facets?.shape[key]}
            onClick={() => pick('shape', key)}
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

      <Section title="Поле">
        {topFields.length === 0 && <div className="px-2 py-1 text-xs text-text-secondary">нет данных</div>}
        {topFields.map(({ value: field, count }) => (
          <Row key={field} active={has(filters.field, field)} count={count} onClick={() => pick('field', field)}>
            <span className="font-mono text-[11px]">{field}</span>
          </Row>
        ))}
      </Section>

      <div className="mt-auto px-2 py-1" />
    </div>
  )
}
