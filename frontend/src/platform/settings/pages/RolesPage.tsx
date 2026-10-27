import { Plus, UserCog } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { clickableRow, ROW_FOCUS } from '@/components/ui/clickableRow'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { cn } from '@/lib/cn'
import { useCan } from '@/lib/can'
import { useRouter } from '@/lib/router'
import { useRoles } from '@/platform/settings/api/access'
import { ColGroup, ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'

const CELL = 'py-1.5 pr-3 align-top'

const COLUMNS: ColumnDef[] = [
  { key: 'name', label: 'Название', width: 200 },
  { key: 'description', label: 'Описание', width: 320, flex: true },
  { key: 'groups', label: 'Групп', width: 80 },
  { key: 'builtin', label: 'Встроенная', width: 112 },
]

/**
 * Роли: набор уровней по модулям и платформе. Роль сама никому не даёт
 * прав — их получают участники групп, которым она назначена.
 */
export function RolesPage() {
  const roles = useRoles()
  const can = useCan()
  const { navigate } = useRouter()
  const cols = useColumnWidths('settings-roles-columns', COLUMNS)

  if (roles.isLoading) return <FullPageSpinner />
  if (roles.isError || !roles.data) {
    return (
      <div className="p-6">
        <ErrorState message={roles.error?.message ?? 'Не удалось загрузить роли'} onRetry={() => roles.refetch()} />
      </div>
    )
  }

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-5 flex items-start justify-between gap-4">
        <div>
          <h1 className="text-base font-semibold text-text">Роли</h1>
          <p className="max-w-2xl text-xs text-text-secondary">
            Роль задаёт уровень доступа к каждому модулю и к настройкам платформы. Права получают
            участники групп, которым назначена роль.
          </p>
        </div>
        {can.platform.admin && (
          <Button variant="primary" className="shrink-0 whitespace-nowrap" onClick={() => navigate('/settings/roles/new')}>
            <Plus size={14} aria-hidden />
            Новая роль
          </Button>
        )}
      </div>

      {roles.data.length === 0 ? (
        <EmptyState icon={UserCog} title="Ролей нет" description="Создайте роль и назначьте её группе." />
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
              {roles.data.map((r) => (
                <tr
                  key={r.id}
                  {...clickableRow(() => navigate(`/settings/roles/${r.id}`))}
                  className={cn(ROW_FOCUS, 'cursor-pointer border-b border-grid hover:bg-row-hover')}
                >
                  <td className={`${CELL} break-words font-medium text-text`}>{r.name}</td>
                  <td className={`${CELL} break-words text-text-secondary`}>{r.description || '—'}</td>
                  <td className={`${CELL} tabular-nums text-text`}>{r.groups}</td>
                  <td className={`${CELL} text-text-secondary`}>{r.builtin ? 'да' : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
