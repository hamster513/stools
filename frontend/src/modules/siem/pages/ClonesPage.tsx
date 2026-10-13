import { Copy } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useClones } from '@/modules/siem/api/queries'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { Link, useSearchParams } from '@/lib/router'
import { ColGroup, ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'
import { CompareView } from './clones/CompareView'

const COLUMNS: ColumnDef[] = [
  { key: 'a', label: 'Правило A', width: 360 },
  { key: 'b', label: 'Правило B', width: 360, flex: true },
  { key: 'similarity', label: 'Похожесть', width: 96, align: 'right' },
]

/**
 * Клоны правил: список пар и сравнение пары бок о бок.
 *
 * Пара задаётся адресом (`?a=…&b=…`), чтобы на сравнение можно было
 * дать ссылку коллеге: спор о том, какое из двух правил лишнее,
 * ведётся не в одиночку.
 */
export function ClonesPage({ snapshotId }: { snapshotId: number }) {
  const params = useSearchParams()
  const a = params.get('a')
  const b = params.get('b')
  const clones = useClones(snapshotId)
  const cols = useColumnWidths('siem-clones-columns', COLUMNS)

  if (clones.isLoading) return <FullPageSpinner />
  if (clones.isError || !clones.data) {
    const message =
      clones.error instanceof ApiRequestError ? clones.error.message : 'Не удалось загрузить клоны'
    return (
      <div className="p-6">
        <ErrorState message={message} onRetry={() => clones.refetch()} />
      </div>
    )
  }

  if (a !== null && b !== null) {
    return <CompareView snapshotId={snapshotId} ruleA={a} ruleB={b} pairs={clones.data} />
  }

  return (
    <div className="flex h-full min-h-0 flex-col overflow-y-auto p-6">
      <div className="mb-5">
        <h1 className="text-base font-semibold text-text">Клоны правил</h1>
        <p className="max-w-2xl text-xs text-text-secondary">
          Пары правил с почти одинаковым набором msgid, полей и фильтров. Обычно это копия,
          которую забыли удалить, или два правила, которые надо было сделать одним. Откройте
          пару — расхождения подсвечены.
        </p>
      </div>

      {clones.data.length === 0 ? (
        <EmptyState
          icon={Copy}
          title="Клонов не найдено"
          description="Ни у одной пары правил сигнатуры не совпадают настолько, чтобы считать их копиями."
        />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs" style={cols.tableStyle}>
            <ColGroup cols={cols} />
            <thead>
              <tr className="border-b border-grid text-left text-[11px] tracking-wide text-text-secondary uppercase">
                <ResizableHeader cols={cols} className="py-2 pr-3" />
              </tr>
            </thead>
            <tbody>
              {clones.data.map((c) => {
                const to = `/siem/snapshots/${snapshotId}/clones?a=${encodeURIComponent(c.rule_a)}&b=${encodeURIComponent(c.rule_b)}`
                return (
                  <tr key={`${c.rule_a}|${c.rule_b}`} className="border-b border-grid hover:bg-row-hover">
                    <td className="py-1.5 pr-3 font-mono">
                      <Link to={to} className="block truncate text-text hover:text-primary" title={c.rule_a}>{c.rule_a}</Link>
                    </td>
                    <td className="py-1.5 pr-3 font-mono">
                      <Link to={to} className="block truncate text-text hover:text-primary" title={c.rule_b}>{c.rule_b}</Link>
                    </td>
                    <td className="py-1.5 pr-3 text-right font-mono tabular-nums text-text-secondary">
                      <Link to={to} className="block hover:text-primary">{Math.round(c.similarity * 100)}%</Link>
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
