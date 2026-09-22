import { AlertTriangle, FolderTree, Monitor } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { usePolicies, useServers } from '@/modules/ksc/api/queries'
import type { PolicyGroup } from '@/modules/ksc/api/types'
import { SeverityBadge } from '@/modules/ksc/components/SeverityBadge'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { Link } from '@/lib/router'

function when(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'никогда'
}

function GroupRow({ group, serverId }: { group: PolicyGroup; serverId: number }) {
  const hasPolicyNone = group.findings.some((f) => f.check === 'POLICY_NONE')
  return (
    <tr className="border-t border-grid align-top">
      <td className="py-2 pr-3" style={{ paddingLeft: group.level * 16 + 8 }}>
        <div className="flex items-center gap-1.5 text-text">
          <FolderTree size={13} className="shrink-0 text-text-secondary" aria-hidden />
          <span className="truncate" title={group.path}>{group.name}</span>
        </div>
        <div className="mt-0.5 flex items-center gap-1 text-[11px] text-text-secondary">
          <Monitor size={11} aria-hidden /> {group.hosts}
        </div>
      </td>
      <td className="py-2 pr-3">
        {group.policies.length === 0 && !hasPolicyNone && <span className="text-text-secondary">—</span>}
        <ul className="flex flex-col gap-1">
          {group.policies.map((p) => (
            <li key={p.id}>
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-text">{p.name}</span>
                <span className="text-[11px] text-text-secondary">{p.product}</span>
                <span className="text-[11px] text-text-secondary">{p.inherited ? 'унаследована' : 'своя'}</span>
                {!p.active && <span className="text-[11px] text-text-secondary">неактивна</span>}
              </div>
              {p.has_contents && (
                <div className="mt-0.5 flex items-center gap-1.5 text-[11px] text-text-secondary">
                  {p.locks && (p.locks.with_lock_flag > 0 ? <span>замков {p.locks.locked} из {p.locks.with_lock_flag}</span> : <span>замки не распознаны</span>)}
                  <Link to={`/ksc/servers/${serverId}/policies/${p.id}`} className="text-primary hover:underline">содержимое</Link>
                </div>
              )}
              {p.accept_parent === false && (
                <div className="flex items-center gap-1 text-[11px] text-risk-medium"><AlertTriangle size={11} aria-hidden /> не принимает родительскую</div>
              )}
            </li>
          ))}
        </ul>
        {hasPolicyNone && <div className="mt-1 text-[11px] font-medium text-risk-high">нет политики</div>}
      </td>
      <td className="py-2 pr-3">
        {group.tasks.length === 0 && <span className="text-text-secondary">—</span>}
        <ul className="flex flex-col gap-1">
          {group.tasks.map((t) => (
            <li key={t.id}>
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-text">{t.type}</span>
                <span className="text-[11px] text-text-secondary">{t.name}</span>
                {t.inherited && <span className="text-[11px] text-text-secondary">унасл.</span>}
              </div>
              <div className="mt-0.5 flex flex-wrap items-center gap-1.5 text-[11px] text-text-secondary">
                <span>последний запуск {when(t.last_run_at)}</span>
                <span>
                  успех {t.ok} · предупр. {t.warning} · <span className={t.failed > 0 ? 'font-medium text-risk-high' : undefined}>провал {t.failed}</span>
                </span>
              </div>
            </li>
          ))}
        </ul>
      </td>
      <td className="py-2">
        {group.findings.length === 0 && <span className="text-text-secondary">—</span>}
        <div className="flex flex-wrap gap-1">
          {group.findings.map((f) => (
            <Link key={f.key} to={`/ksc/servers/${serverId}/findings?check=${f.check}`}>
              <SeverityBadge severity={f.severity} />
            </Link>
          ))}
        </div>
      </td>
    </tr>
  )
}

/** Дерево групп администрирования снапшота: действующие политики, групповые задачи, их находки. */
export function PoliciesPage({ serverId }: { serverId: number }) {
  const servers = useServers()
  const server = servers.data?.find((s) => s.id === serverId)
  const snapshotId = server?.last_snapshot_id ?? undefined
  const policies = usePolicies(snapshotId)

  if (servers.isLoading) return <FullPageSpinner />
  if (snapshotId === undefined) {
    return <div className="p-6"><EmptyState icon={FolderTree} title="Снапшотов нет" description="Загрузите выгрузку или запустите сбор из KSC в настройках модуля." /></div>
  }
  if (policies.isLoading) return <FullPageSpinner />
  if (policies.isError || !policies.data) {
    const msg = policies.error instanceof ApiRequestError ? policies.error.message : 'Не удалось загрузить политики и задачи'
    return <div className="p-6"><ErrorState message={msg} onRetry={() => policies.refetch()} /></div>
  }

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-4">
        <h1 className="text-base font-semibold text-text">Политики и задачи</h1>
        <p className="max-w-2xl text-xs text-text-secondary">Действующие политики и групповые задачи по дереву групп администрирования снапшота #{snapshotId}.</p>
      </div>
      <table className="w-full text-xs">
        <thead className="text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
          <tr>
            <th className="w-1/4 py-1.5 pr-3 pl-2 text-left">Группа</th>
            <th className="w-1/3 py-1.5 pr-3 text-left">Политики</th>
            <th className="w-1/4 py-1.5 pr-3 text-left">Задачи</th>
            <th className="py-1.5 text-left">Находки</th>
          </tr>
        </thead>
        <tbody>
          {policies.data.groups.map((g) => (
            <GroupRow key={g.id} group={g} serverId={serverId} />
          ))}
        </tbody>
      </table>
      {policies.data.groups.length === 0 && (
        <div className="mt-4"><EmptyState icon={FolderTree} title="Групп нет" description="В снапшоте нет групп администрирования." /></div>
      )}
    </div>
  )
}
