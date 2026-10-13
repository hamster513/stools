import { useEffect, useMemo, useRef, useState } from 'react'
import { clickableRow, ROW_FOCUS } from '@/components/ui/clickableRow'
import { useVirtualizer } from '@tanstack/react-virtual'
import { CheckCircle2, ListTree, Search, Sparkles, XCircle } from 'lucide-react'
import { useRules } from '@/modules/siem/api/queries'
import type { AttackStatus, RuleAttackInfo, RuleListItem } from '@/modules/siem/api/types'
import { tacticLabel } from '@/modules/siem/api/types'
import { useSearchParams } from '@/lib/router'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { ErrorState } from '@/components/ui/ErrorState'
import { EmptyState } from '@/components/ui/EmptyState'
import { ApiRequestError } from '@/api/client'
import { cn } from '@/lib/cn'
import { AttentionBadge, attentionLevel } from '@/modules/siem/components/ui/AttentionBadge'
import { RuleDetailDrawer } from './rules/RuleDetailDrawer'
import { useRouter } from '@/lib/router'
import { FiltersButton, FilterChips, type FilterChip } from '@/platform/filters/FiltersBar'
import { useFiltersPanel } from '@/platform/filters/useFiltersPanel'
import { ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'

const ROW_HEIGHT = 32

const COLUMNS: ColumnDef[] = [
  { key: 'name', label: 'Имя', width: 420, flex: true },
  { key: 'author', label: 'Автор', width: 128 },
  { key: 'category', label: 'Категория', width: 112 },
  { key: 'msgid', label: 'msgid', width: 80, align: 'right' },
  { key: 'attention', label: 'Внимание', width: 144 },
  { key: 'attack', label: 'ATT&CK', width: 224 },
  { key: 'scoped', label: 'Ограничено', width: 112 },
]

/**
 * Фасеты по автору/категории/группе и переключатель «только ограниченные
 * списком» бэкенд для /api/siem/rules не считает — экран инвентаря забирает
 * весь снапшот (187 правил, немного) и агрегирует на клиенте.
 */
//: Фильтр по разметке ATT&CK. «Не размечено» — самый нужный: он
//: показывает, чего ещё не касались.
const ATTACK_FILTERS: { key: AttackStatus | 'all'; label: string }[] = [
  { key: 'all', label: 'вся разметка' },
  { key: 'suggested', label: 'предложено' },
  { key: 'confirmed', label: 'подтверждено' },
  { key: 'unmapped', label: 'не размечено' },
]

export function RulesPage({ snapshotId }: { snapshotId: number }) {
  const searchParams = useSearchParams()
  const query = useRules({ snapshot_id: snapshotId, limit: 1000 })
  const [author, setAuthor] = useState<string | undefined>()
  const [category, setCategory] = useState<string | undefined>()
  const [onlyScoped, setOnlyScoped] = useState(searchParams.get('scoped') === '1')
  const [onlyAttention, setOnlyAttention] = useState(searchParams.get('attention') === '1')
  const [attackFilter, setAttackFilter] = useState<AttackStatus | 'all'>(
    (searchParams.get('attack') as AttackStatus) ?? 'all',
  )
  const [searchInput, setSearchInput] = useState(searchParams.get('q') ?? '')
  const q = useDebouncedValue(searchInput, 200)
  const [openUuid, setOpenUuid] = useState<string | null>(null)
  const parentRef = useRef<HTMLDivElement>(null)
  const filtersPanel = useFiltersPanel('siem-rules')
  const cols = useColumnWidths('siem-rules-columns', COLUMNS)

  const allItems = useMemo(() => query.data?.items ?? [], [query.data])

  const authorFacet = useMemo(() => {
    const out: Record<string, number> = {}
    for (const r of allItems) out[r.author] = (out[r.author] ?? 0) + 1
    return out
  }, [allItems])

  const categoryFacet = useMemo(() => {
    const out: Record<string, number> = {}
    for (const r of allItems) if (!author || r.author === author) out[r.category] = (out[r.category] ?? 0) + 1
    return out
  }, [allItems, author])

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return allItems.filter((r) => {
      if (author && r.author !== author) return false
      if (category && r.category !== category) return false
      if (onlyScoped && !r.scoped) return false
      if (onlyAttention && attentionLevel(r.parse_status, r.open_finding_count, r.max_severity) === 'clean')
        return false
      if (attackFilter !== 'all' && (r.attack?.status ?? 'unmapped') !== attackFilter) return false
      if (needle && !r.name.toLowerCase().includes(needle)) return false
      return true
    })
  }, [allItems, author, category, onlyScoped, onlyAttention, attackFilter, q])

  const virtualizer = useVirtualizer({
    count: filtered.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 12,
  })

  useEffect(() => {
    virtualizer.scrollToIndex(0)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [author, category, onlyScoped, onlyAttention, attackFilter, q])

  const groupsInView = useMemo(() => {
    const out = new Set<string>()
    for (const r of filtered) {
      if (r.attack?.group) out.add(r.attack.group)
    }
    return out.size
  }, [filtered])

  const errorMessage =
    query.error instanceof ApiRequestError ? query.error.message : query.isError ? 'Не удалось загрузить правила' : null

  // Что выбрано в боковой панели, пока она свёрнута.
  const chips: FilterChip[] = []
  if (author) chips.push({ label: `автор ${author}`, clear: () => setAuthor(undefined) })
  if (category) chips.push({ label: `категория ${category}`, clear: () => setCategory(undefined) })

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex shrink-0 flex-wrap items-center gap-3 border-b border-grid bg-surface px-4 py-2.5">
        <h1 className="text-sm font-semibold text-text">Инвентарь правил</h1>
        <FiltersButton open={filtersPanel.open} onToggle={filtersPanel.toggle} count={chips.length} />
        <div className="relative max-w-sm flex-1">
          <Search size={14} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-text-secondary" aria-hidden />
          <input
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder="Поиск по имени правила…"
            className="w-full rounded border border-border bg-app-bg py-1.5 pr-3 pl-8 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
          />
        </div>
        <label className="flex items-center gap-1.5 text-xs text-text-secondary">
          <input
            type="checkbox"
            checked={onlyAttention}
            onChange={(e) => setOnlyAttention(e.target.checked)}
            className="accent-primary"
          />
          <span>требуют внимания</span>
        </label>
        <label className="flex items-center gap-1.5 text-xs text-text-secondary">
          <input type="checkbox" checked={onlyScoped} onChange={(e) => setOnlyScoped(e.target.checked)} className="accent-primary" />
          <span>только ограниченные списком</span>
        </label>
        <div className="flex items-center gap-1.5">
          {ATTACK_FILTERS.map(({ key, label }) => (
            <button
              key={key}
              type="button"
              onClick={() => setAttackFilter(key)}
              className={cn(
                'rounded border px-2 py-0.5 text-[11px] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring',
                attackFilter === key
                  ? 'border-primary/60 bg-primary/10 text-text'
                  : 'border-grid text-text-secondary hover:bg-row-hover hover:text-text',
              )}
              aria-pressed={attackFilter === key}
              title="Разметка ATT&CK"
            >
              {label}
            </button>
          ))}
        </div>
        <div className="font-mono text-xs tabular-nums text-text-secondary">
          {filtered.length} из {allItems.length}
          {/* Разметка ведётся по группам: сорок четыре решения на сто
              восемьдесят семь правил, и самая большая группа — двадцать
              девять. Одно число правил завышает объём работы втрое. */}
          {attackFilter !== 'all' && groupsInView > 0 && (
            <span className="ml-1.5 text-text-secondary/70">
              · {groupsInView} {groupsInView === 1 ? 'группа' : 'групп'}
            </span>
          )}
        </div>
        {!filtersPanel.open && <FilterChips chips={chips} />}
      </header>

      <div className="flex min-h-0 flex-1">
        {filtersPanel.open && (
          <div className="flex h-full w-56 shrink-0 flex-col overflow-y-auto border-r border-grid bg-surface">
            <div className="border-b border-grid px-2 py-3">
              <div className="mb-1.5 px-2 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">Автор</div>
              {Object.entries(authorFacet)
                .sort((a, b) => b[1] - a[1])
                .map(([a, cnt]) => (
                  <button
                    key={a}
                    type="button"
                    onClick={() => setAuthor((prev) => (prev === a ? undefined : a))}
                    className={cn(
                      'flex w-full items-center justify-between rounded px-2 py-1.5 text-left text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring',
                      author === a ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text',
                    )}
                  >
                    <span className="truncate">{a}</span>
                    <span className="font-mono tabular-nums text-[11px]">{cnt}</span>
                  </button>
                ))}
            </div>
            <div className="px-2 py-3">
              <div className="mb-1.5 px-2 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">Категория</div>
              {Object.entries(categoryFacet)
                .sort((a, b) => b[1] - a[1])
                .map(([c, cnt]) => (
                  <button
                    key={c}
                    type="button"
                    onClick={() => setCategory((prev) => (prev === c ? undefined : c))}
                    className={cn(
                      'flex w-full items-center justify-between rounded px-2 py-1.5 text-left text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring',
                      category === c ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text',
                    )}
                  >
                    <span className="truncate font-mono">{c}</span>
                    <span className="font-mono tabular-nums text-[11px]">{cnt}</span>
                  </button>
                ))}
            </div>
          </div>
        )}

        <div className="min-w-0 flex-1 bg-app-bg">
          {query.isLoading && <FullPageSpinner />}
          {errorMessage && (
            <div className="p-6">
              <ErrorState message={errorMessage} onRetry={() => query.refetch()} />
            </div>
          )}
          {!query.isLoading && !errorMessage && filtered.length === 0 && (
            <div className="p-6">
              <EmptyState icon={ListTree} title="Правил не найдено" description="Измените фильтры слева или запрос поиска." />
            </div>
          )}
          {!query.isLoading && !errorMessage && filtered.length > 0 && (
            <div ref={parentRef} data-col-resize-root className="h-full overflow-auto">
              {/* Имя правила — главная колонка: забирает свободное место, её
                  ширина — минимум. Заголовок и строки делят один шаблон сетки,
                  поэтому колонки не разъезжаются. Длинные имена обрезаются,
                  полное видно в подсказке. Внимание — маркировка вместо голого
                  счётчика находок; ATT&CK — ярлык техники и тактика, название
                  и обоснование — в подробностях. */}
              <div className="sticky top-0 z-10 grid border-b border-grid bg-surface text-[11px] tracking-wide text-text-secondary uppercase" style={cols.gridStyle}>
                <ResizableHeader cols={cols} as="div" className="px-2 py-2" />
              </div>
              <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
                {virtualizer.getVirtualItems().map((row) => {
                  const rule = filtered[row.index]
                  return (
                    <div
                      key={rule.uuid}
                      {...clickableRow(() => setOpenUuid(rule.uuid))}
                      className={cn(ROW_FOCUS, 'absolute top-0 left-0 grid w-full cursor-pointer items-center border-b border-grid text-xs hover:bg-row-hover')}
                      style={{ ...cols.gridStyle, height: ROW_HEIGHT, transform: `translateY(${row.start}px)` }}
                    >
                      <div className="min-w-0 truncate px-2 font-mono text-text" title={rule.name}>
                        {rule.name}
                      </div>
                      <div className="min-w-0 truncate px-2 text-text-secondary">{rule.author}</div>
                      <div className="min-w-0 truncate px-2 font-mono text-text-secondary">
                        {rule.category}/{rule.group}
                      </div>
                      <div className="min-w-0 px-2 text-right font-mono tabular-nums text-text-secondary">{rule.msgid_count}</div>
                      <div className="min-w-0 overflow-hidden px-2">
                        <RuleAttentionCell snapshotId={snapshotId} rule={rule} />
                      </div>
                      <div className="min-w-0 truncate px-2">
                        <RuleAttackCell attack={rule.attack} />
                      </div>
                      <div className="min-w-0 px-2">
                        {rule.scoped ? (
                          <CheckCircle2 size={14} className="text-kind-accepted" aria-label="ограничено" />
                        ) : (
                          <XCircle size={14} className="text-text-secondary/50" aria-label="не ограничено" />
                        )}
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          )}
        </div>
      </div>

      <RuleDetailDrawer uuid={openUuid} snapshotId={snapshotId} onClose={() => setOpenUuid(null)} />
    </div>
  )
}

/**
 * Разметка правила в списке: идентификатор техники и тактика.
 *
 * Название и обоснование сюда не помещаются и не нужны — в списке
 * нужен ярлык, по которому видно, размечено ли правило и чем. Значок
 * отличает предложение модели от подтверждения человеком: без этого
 * непроверенная разметка выглядит как установленный факт.
 */
function RuleAttackCell({ attack }: { attack: RuleAttackInfo | undefined }) {
  const first = attack?.techniques[0]
  if (!attack || !first) {
    return <span className="text-xs text-text-secondary/60">—</span>
  }
  const rest = attack.techniques.length - 1
  return (
    <span className="flex items-center gap-1.5 truncate" title={first.name_ru ?? first.name}>
      {attack.status === 'confirmed' ? (
        <CheckCircle2 size={12} className="shrink-0 text-kind-accepted" aria-label="подтверждено человеком" />
      ) : (
        <Sparkles size={12} className="shrink-0 text-attack-suggested" aria-label="предложено моделью" />
      )}
      <span className="font-mono text-xs text-primary">{first.technique_id}</span>
      <span className="truncate text-xs text-text-secondary">
        {first.tactics.map(tacticLabel).join(', ')}
      </span>
      {rest > 0 && <span className="shrink-0 text-xs text-text-secondary">+{rest}</span>}
    </span>
  )
}

/**
 * Маркировка правила. Клик уводит в разбор находок ровно по этому правилу:
 * гигиена контента — не отдельный раздел, а продолжение инвентаря, и путь
 * туда начинается с правила, у которого что-то не так.
 */
function RuleAttentionCell({ snapshotId, rule }: { snapshotId: number; rule: RuleListItem }) {
  const { navigate } = useRouter()
  const level = attentionLevel(rule.parse_status, rule.open_finding_count, rule.max_severity)

  if (level === 'clean') {
    return <AttentionBadge level={level} count={0} />
  }
  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation()
        navigate(`/siem/snapshots/${snapshotId}/hygiene?object_uuid=${encodeURIComponent(rule.uuid)}`)
      }}
      className="rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
      title="Открыть находки по этому правилу"
    >
      <AttentionBadge level={level} count={rule.open_finding_count} />
    </button>
  )
}
