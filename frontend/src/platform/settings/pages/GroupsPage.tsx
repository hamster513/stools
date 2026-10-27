import { useState } from 'react'
import { Plus, UsersRound } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { clickableRow, ROW_FOCUS } from '@/components/ui/clickableRow'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { cn } from '@/lib/cn'
import { useCan } from '@/lib/can'
import { useRouter } from '@/lib/router'
import { FilterChips, FiltersButton, type FilterChip } from '@/platform/filters/FiltersBar'
import { useFiltersPanel } from '@/platform/filters/useFiltersPanel'
import { useGroups } from '@/platform/settings/api/access'
import { ColGroup, ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'

const CELL = 'py-1.5 pr-3 align-top'

const COLUMNS: ColumnDef[] = [
  { key: 'name', label: 'Название', width: 200, flex: true },
  { key: 'source', label: 'Источник', width: 104 },
  { key: 'external', label: 'Имя в OIDC', width: 200 },
  { key: 'role', label: 'Роль', width: 176 },
  { key: 'members', label: 'Участников', width: 104 },
]

type SourceFilter = 'all' | 'local' | 'oidc'

const SOURCE_FILTERS: Array<{ value: SourceFilter; label: string }> = [
  { value: 'all', label: 'все' },
  { value: 'local', label: 'локальные' },
  { value: 'oidc', label: 'OIDC' },
]

/**
 * Группы: кому выдана роль. Локальной группе администратор ведёт состав
 * сам, группа OIDC наполняется провайдером при входе.
 */
export function GroupsPage() {
  const groups = useGroups()
  const can = useCan()
  const { navigate } = useRouter()
  const cols = useColumnWidths('settings-groups-columns', COLUMNS)
  const filtersPanel = useFiltersPanel('settings-groups')
  const [source, setSource] = useState<SourceFilter>('all')

  if (groups.isLoading) return <FullPageSpinner />
  if (groups.isError || !groups.data) {
    return (
      <div className="p-6">
        <ErrorState message={groups.error?.message ?? 'Не удалось загрузить группы'} onRetry={() => groups.refetch()} />
      </div>
    )
  }

  const rows = groups.data.filter((g) => source === 'all' || g.source === source)
  const chips: FilterChip[] = []
  if (source !== 'all') {
    const title = SOURCE_FILTERS.find((f) => f.value === source)?.label
    chips.push({ label: `Источник: ${title}`, clear: () => setSource('all') })
  }

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-5 flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-base font-semibold text-text">Группы</h1>
            <FiltersButton open={filtersPanel.open} onToggle={filtersPanel.toggle} count={chips.length} />
          </div>
          <p className="max-w-2xl text-xs text-text-secondary">
            Группа даёт участникам свою роль. Если пользователь состоит в нескольких группах, в каждой
            области действует высший из уровней.
          </p>
        </div>
        {can.platform.admin && (
          <Button variant="primary" className="shrink-0 whitespace-nowrap" onClick={() => navigate('/settings/groups/new')}>
            <Plus size={14} aria-hidden />
            Новая группа
          </Button>
        )}
      </div>

      {!filtersPanel.open && chips.length > 0 && (
        <div className="mb-4 flex">
          <FilterChips chips={chips} />
        </div>
      )}
      {filtersPanel.open && (
        <fieldset className="mb-4">
          <legend className="mb-1 block text-xs font-medium text-text">Источник</legend>
          <div className="flex flex-wrap gap-1.5">
            {SOURCE_FILTERS.map((f) => (
              <button
                key={f.value}
                type="button"
                aria-pressed={source === f.value}
                onClick={() => setSource(f.value)}
                className={cn(
                  'rounded border px-2 py-0.5 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring',
                  source === f.value
                    ? 'border-primary bg-primary text-primary-text'
                    : 'border-border text-text hover:bg-row-hover',
                )}
              >
                {f.label}
              </button>
            ))}
          </div>
        </fieldset>
      )}

      {rows.length === 0 ? (
        <EmptyState
          icon={UsersRound}
          title="Групп нет"
          description={source === 'all' ? 'Создайте группу и назначьте ей роль.' : 'Под выбранный источник групп нет.'}
        />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full max-w-5xl text-xs" style={cols.tableStyle}>
            <ColGroup cols={cols} />
            <thead>
              <tr className="border-b border-grid text-left text-[11px] tracking-wide text-text-secondary uppercase">
                <ResizableHeader cols={cols} className="py-1.5 pr-3" />
              </tr>
            </thead>
            <tbody>
              {rows.map((g) => (
                <tr
                  key={g.id}
                  {...clickableRow(() => navigate(`/settings/groups/${g.id}`))}
                  className={cn(ROW_FOCUS, 'cursor-pointer border-b border-grid hover:bg-row-hover')}
                >
                  <td className={`${CELL} break-words font-medium text-text`}>{g.name}</td>
                  <td className={`${CELL} text-text-secondary`}>{g.source === 'oidc' ? 'OIDC' : 'локальная'}</td>
                  <td className={`${CELL} break-all font-mono text-text-secondary`}>{g.external_name ?? '—'}</td>
                  <td className={`${CELL} break-words text-text`}>{g.role_name}</td>
                  <td className={`${CELL} tabular-nums text-text`}>{g.members}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
