import { FolderTree } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { usePolicyScope } from '@/modules/ksc/api/queries'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { Link } from '@/lib/router'

/** Вкладка «Где действует»: группы, где политика действует (своя или унаследованная), и хосты прямо в них. */
export function ScopeTab({ serverId, snapshotId, policyId }: { serverId: number; snapshotId: number; policyId: number }) {
  const scope = usePolicyScope(snapshotId, policyId)

  if (scope.isLoading) return <FullPageSpinner />
  if (scope.isError || !scope.data) {
    const msg = scope.error instanceof ApiRequestError ? scope.error.message : 'Не удалось загрузить группы политики'
    return <ErrorState message={msg} onRetry={() => scope.refetch()} />
  }
  const { groups, hosts } = scope.data

  return (
    <>
      <p className="mb-3 text-xs text-text-secondary">
        Хостов под политикой: <span className="font-mono tabular-nums text-text">{hosts}</span>
        {hosts > 0 && (
          <Link to={`/ksc/servers/${serverId}/hosts?policy=${policyId}`} className="ml-2 text-primary hover:underline">хосты под политикой</Link>
        )}
      </p>
      {groups.length === 0 ? (
        <EmptyState icon={FolderTree} title="Групп нет" description="Политика не действует ни в одной группе снапшота. Если выгрузка импортирована до появления привязки, пересчитайте снапшот на экране «Снапшоты»." />
      ) : (
        <table className="w-full text-xs">
          <thead className="text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
            <tr>
              <th className="py-1.5 pr-3 pl-2 text-left">Группа</th>
              <th className="w-40 py-1.5 pr-3 text-left">Политика в группе</th>
              <th className="w-24 py-1.5 pr-2 text-right">Хостов</th>
            </tr>
          </thead>
          <tbody>
            {groups.map((g) => (
              <tr key={g.group_id} className="border-t border-grid">
                <td className="py-1.5 pr-3 pl-2 text-text">{g.path}</td>
                <td className="py-1.5 pr-3 text-text-secondary">{g.own ? 'своя' : 'унаследованная'}</td>
                <td className="py-1.5 pr-2 text-right font-mono tabular-nums text-text-secondary">{g.hosts}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {groups.length > 0 && <p className="mt-2 text-[11px] text-text-secondary">В каждой группе — только хосты прямо в ней, без подгрупп.</p>}
    </>
  )
}
