import { ArrowRight } from 'lucide-react'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { cn } from '@/lib/cn'
import { Link } from '@/lib/router'
import { moduleTitle } from '@/platform/modules'
import { useDataStatus, type DataItem } from '@/platform/settings/api/dataStatus'
import { ColGroup, ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'

const CELL = 'py-1.5 pr-3'

const COLUMNS: ColumnDef[] = [
  { key: 'module', label: 'Модуль', width: 168 },
  { key: 'title', label: 'База или выгрузка', width: 240, flex: true },
  { key: 'updated', label: 'Обновлено', width: 168 },
  { key: 'state', label: 'Состояние', width: 112 },
  { key: 'source', label: 'Источник', width: 160 },
  { key: 'go', label: '→', width: 40, resizable: false, align: 'right' },
]

const STATE: Record<DataItem['state'], { label: string; className: string }> = {
  fresh: { label: 'свежо', className: 'bg-kind-accepted/10 text-kind-accepted' },
  stale: { label: 'устарело', className: 'bg-risk-medium/10 text-risk-medium' },
  missing: { label: 'нет данных', className: 'bg-risk-medium/10 text-risk-medium' },
  running: { label: 'обновляется', className: 'bg-kind-4/10 text-kind-4' },
}

const pad = (n: number) => String(n).padStart(2, '0')

/** «20.10 03:10 · 5 дн. назад». */
function updated(iso: string): string {
  const d = new Date(iso)
  const at = `${pad(d.getDate())}.${pad(d.getMonth() + 1)} ${pad(d.getHours())}:${pad(d.getMinutes())}`
  const min = Math.floor((Date.now() - d.getTime()) / 60_000)
  const ago =
    min < 1 ? 'только что' : min < 60 ? `${min} мин. назад` : min < 1440 ? `${Math.floor(min / 60)} ч. назад` : `${Math.floor(min / 1440)} дн. назад`
  return `${at} · ${ago}`
}

/**
 * Первый экран настроек: базы, справочники и выгрузки всех модулей и их
 * свежесть. Отсюда видно, что пора обновить, и «→» ведёт к секции модуля,
 * где это делается.
 */
export function DataStatusPage() {
  const status = useDataStatus()
  const cols = useColumnWidths('settings-data-status', COLUMNS)

  if (status.isLoading) return <FullPageSpinner />
  if (status.isError || !status.data) {
    return (
      <div className="p-6">
        <ErrorState
          message={status.error?.message ?? 'Не удалось загрузить сводку данных'}
          onRetry={() => status.refetch()}
        />
      </div>
    )
  }

  const items = status.data.items
  const outdated = items.filter((i) => i.state === 'stale' || i.state === 'missing').length

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-5">
        <div className="flex items-center gap-3">
          <h1 className="text-base font-semibold text-text">Данные</h1>
          <span className={cn('text-xs', outdated ? 'text-risk-medium' : 'text-kind-accepted')}>
            {outdated ? `устарело: ${outdated}` : 'всё свежо'}
          </span>
        </div>
        <p className="max-w-2xl text-xs text-text-secondary">
          Базы, справочники и выгрузки всех модулей; свежесть считается от последнего обновления
        </p>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full max-w-5xl text-xs" style={cols.tableStyle}>
          <ColGroup cols={cols} />
          <thead>
            <tr className="border-b border-grid text-left text-[11px] tracking-wide text-text-secondary uppercase">
              <ResizableHeader cols={cols} className="py-1.5 pr-3" />
            </tr>
          </thead>
          <tbody>
            {items.map((item, i) => {
              // Модуль подписан только в первой строке своей группы: сервер отдаёт строки по модулям подряд.
              const first = i === 0 || items[i - 1].module !== item.module
              const outdatedRow = item.state === 'stale' || item.state === 'missing'
              const badge = STATE[item.state]
              return (
                <tr
                  key={`${item.module}:${item.key}`}
                  className={cn('border-b border-grid hover:bg-row-hover', outdatedRow && 'bg-risk-medium/5')}
                >
                  <td className={`${CELL} break-words text-text`}>{first ? moduleTitle(item.module) : ''}</td>
                  <td className={`${CELL} break-words text-text`}>
                    {item.title}
                    {item.detail && <span className="text-text-secondary"> · {item.detail}</span>}
                  </td>
                  <td className={`${CELL} tabular-nums text-text-secondary`}>
                    {item.updated_at ? updated(item.updated_at) : ''}
                  </td>
                  <td className={CELL}>
                    <span className={cn('rounded px-1.5 py-0.5 whitespace-nowrap', badge.className)}>{badge.label}</span>
                  </td>
                  <td className={`${CELL} truncate text-text-secondary`} title={item.source ?? undefined}>
                    {item.source ?? ''}
                  </td>
                  <td className="py-1.5 text-right">
                    <Link
                      to={`/settings/${item.module}#${item.anchor}`}
                      className="inline-flex rounded p-0.5 text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
                      aria-label={`К настройке: ${item.title}`}
                      title="к настройке модуля"
                    >
                      <ArrowRight size={14} aria-hidden />
                    </Link>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
