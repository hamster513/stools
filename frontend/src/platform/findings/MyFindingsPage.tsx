import { useState } from 'react'
import { ListChecks } from 'lucide-react'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { clickableRow, ROW_FOCUS } from '@/components/ui/clickableRow'
import { cn } from '@/lib/cn'
import { useRouter } from '@/lib/router'
import { ExportButton } from '@/platform/filters/ExportButton'
import { exportHref } from '@/platform/filters/exportHref'
import { FiltersButton, FilterChips, type FilterChip } from '@/platform/filters/FiltersBar'
import { useFiltersPanel } from '@/platform/filters/useFiltersPanel'
import { MODULES } from '@/platform/modules'
import { ColGroup, ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'
import { findingFacetChips, STATUS_OPTIONS, toggleStatus, toggleValue, valueChips } from './facets'
import { myFindingsParams, useMyFindings } from './queries'
import { StatusBadge } from './StatusBadge'
import type { FindingStatus } from './types'

/** Модули со статусами находок — для фильтра. */
const FINDING_MODULES = ['ad', 'ksc', 'siem', 'vm', 'assets']
const MODULE_OPTIONS = MODULES.filter((m) => FINDING_MODULES.includes(m.id))

/** Тяжесть у модулей в разном регистре (AD — `High`, VM — `high`): цвет и слово по нижнему. */
const SEVERITY: Record<string, { label: string; className: string }> = {
  critical: { label: 'критический', className: 'text-risk-critical' },
  high: { label: 'высокий', className: 'text-risk-high' },
  medium: { label: 'средний', className: 'text-risk-medium' },
  low: { label: 'низкий', className: 'text-risk-low' },
  info: { label: 'инфо', className: 'text-text-secondary' },
}

const CELL = 'py-1.5 pr-3 align-top'

const COLUMNS: ColumnDef[] = [
  { key: 'module', label: 'Модуль', width: 160 },
  { key: 'finding', label: 'Находка', width: 320, flex: true },
  { key: 'severity', label: 'Тяжесть', width: 112 },
  { key: 'status', label: 'Статус', width: 160 },
  { key: 'due', label: 'Срок', width: 160 },
  { key: 'risk', label: 'Риск принят до', width: 128 },
]

function day(value: string): string {
  return new Date(`${value}T00:00:00`).toLocaleDateString('ru-RU')
}

/**
 * «Мои находки» — всё, что назначено мне, во всех модулях: сначала
 * просроченное, затем по сроку и тяжести. Строка ведёт в карточку находки
 * в её модуле, где и меняется статус.
 */
export function MyFindingsPage() {
  const { navigate } = useRouter()
  const [status, setStatus] = useState<FindingStatus[] | undefined>()
  const [module, setModule] = useState<string[] | undefined>()
  const filtersPanel = useFiltersPanel('findings-mine')
  const mine = useMyFindings({ status, module })
  const cols = useColumnWidths('findings-mine-columns', COLUMNS)

  // Чип на каждое выбранное значение: крестик снимает только его.
  const chips: FilterChip[] = findingFacetChips({ status }, (next) => setStatus(next.status))
  chips.push(...valueChips('Модуль', module, (id) => MODULE_OPTIONS.find((m) => m.id === id)?.title ?? id, setModule))

  return (
    <div className="flex h-full min-h-0 flex-col overflow-y-auto p-6">
      <div className="mb-5 flex flex-wrap items-start gap-3">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-base font-semibold text-text">Мои находки</h1>
            <FiltersButton open={filtersPanel.open} onToggle={filtersPanel.toggle} count={chips.length} />
            <ExportButton href={exportHref('/api/findings/mine/export', myFindingsParams({ status, module }))} total={mine.data?.length} disabled={mine.isLoading} />
          </div>
          <p className="max-w-2xl text-xs text-text-secondary">
            Находки всех модулей, где исполнитель — вы. Без фильтра статуса — открытые; сначала
            просроченные, затем по сроку и тяжести. Статус меняется в карточке находки.
          </p>
        </div>
        {!filtersPanel.open && <FilterChips chips={chips} />}
      </div>

      {filtersPanel.open && (
        <div className="mb-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <fieldset>
            <legend className="mb-1 block text-xs font-medium text-text">Статус</legend>
            <div className="flex flex-wrap gap-x-3 gap-y-1">
              {STATUS_OPTIONS.map((o) => (
                <label key={o.value} className="flex items-center gap-1.5 text-xs text-text">
                  <input
                    type="checkbox"
                    checked={status?.includes(o.value) ?? false}
                    onChange={() => setStatus((s) => toggleStatus(s, o.value))}
                  />
                  {o.label}
                </label>
              ))}
            </div>
            <span className="mt-1 block text-xs text-text-secondary">Ничего не выбрано — открытые.</span>
          </fieldset>
          <fieldset>
            <legend className="mb-1 block text-xs font-medium text-text">Модуль</legend>
            <div className="flex flex-wrap gap-x-3 gap-y-1">
              {MODULE_OPTIONS.map((m) => (
                <label key={m.id} className="flex items-center gap-1.5 text-xs text-text">
                  <input type="checkbox" checked={module?.includes(m.id) ?? false} onChange={() => setModule((v) => toggleValue(v, m.id))} />
                  {m.title}
                </label>
              ))}
            </div>
            <span className="mt-1 block text-xs text-text-secondary">Ничего не выбрано — все модули.</span>
          </fieldset>
        </div>
      )}

      {mine.isError ? (
        <ErrorState message={mine.error?.message ?? 'Не удалось загрузить находки'} onRetry={() => mine.refetch()} />
      ) : !mine.data ? (
        <FullPageSpinner />
      ) : mine.data.length === 0 ? (
        <EmptyState
          icon={ListChecks}
          title="Назначенных находок нет"
          description={
            chips.length
              ? 'Под выбранные фильтры ничего не попало. Снимите фильтры, чтобы увидеть все открытые.'
              : 'Когда вас назначат исполнителем находки в любом модуле, она появится здесь.'
          }
        />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs" style={cols.tableStyle}>
            <ColGroup cols={cols} />
            <thead>
              <tr className="border-b border-grid text-left text-[11px] tracking-wide text-text-secondary uppercase">
                <ResizableHeader cols={cols} className="py-1.5 pr-3" />
              </tr>
            </thead>
            <tbody>
              {mine.data.map((f) => {
                const sev = SEVERITY[f.severity.toLowerCase()]
                return (
                  <tr
                    key={`${f.module}|${f.scope_id}|${f.key}`}
                    {...(f.link ? clickableRow(() => navigate(f.link)) : {})}
                    className={cn('border-b border-grid', f.link && 'cursor-pointer hover:bg-row-hover', ROW_FOCUS)}
                  >
                    <td className={CELL}>
                      <span className="inline-block max-w-full truncate rounded border border-border px-1.5 py-0.5 align-top text-[11px] text-text-secondary" title={f.module_title}>
                        {f.module_title}
                      </span>
                    </td>
                    <td className={`${CELL} break-words text-text`}>
                      {f.title || <span className="font-mono text-text-secondary">{f.key}</span>}
                      {!f.present && <span className="ml-2 text-[11px] text-text-secondary">нет в свежих данных</span>}
                    </td>
                    <td className={cn(CELL, 'truncate', sev?.className ?? 'text-text-secondary')}>
                      {sev?.label ?? (f.severity || '—')}
                    </td>
                    <td className={CELL}>
                      <StatusBadge status={f.status} />
                    </td>
                    <td className={cn(CELL, 'tabular-nums', f.overdue ? 'text-kind-1' : 'text-text')}>
                      {f.due_date ? day(f.due_date) : '—'}
                      {f.overdue && <span className="ml-1.5 text-[11px]">просрочено</span>}
                    </td>
                    <td className="truncate py-1.5 tabular-nums text-text-secondary">
                      {f.risk_until ? day(f.risk_until) : '—'}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
