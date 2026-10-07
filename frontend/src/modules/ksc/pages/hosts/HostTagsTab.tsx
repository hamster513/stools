import { Tag } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useHostProfiles } from '@/modules/ksc/api/queries'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { Spinner } from '@/components/ui/Spinner'
import { Link } from '@/lib/router'

/** Вкладка «Теги» панели хоста: каждый тег и профили, в условии активации которых он встречается (выключенные — с пометкой). */
export function HostTagsTab({ snapshotId, hostId, serverId }: { snapshotId: number; hostId: string; serverId: number }) {
  const query = useHostProfiles(snapshotId, hostId)
  if (query.isLoading) return <div className="flex justify-center py-8"><Spinner /></div>
  if (query.isError || !query.data) {
    const msg = query.error instanceof ApiRequestError ? query.error.message : 'Не удалось загрузить теги хоста'
    return <ErrorState message={msg} onRetry={() => query.refetch()} />
  }
  const d = query.data
  if (d.tags === null) return <EmptyState icon={Tag} title="Теги не собраны" description="Сборщик не присылал теги хостов — это не значит, что их нет." />
  if (d.tags.length === 0) return <EmptyState icon={Tag} title="Тегов нет" description="Теги собраны, у этого хоста их нет." />
  const byTag = new Map(d.by_tag.map((t) => [t.tag, t.profiles]))
  return (
    <div className="flex flex-col gap-3">
      {d.tags.map((tag) => {
        const profiles = byTag.get(tag) ?? []
        return (
          <div key={tag}>
            <div className="mb-1"><span className="rounded bg-row-hover px-1.5 py-0.5 text-[11px] text-text">{tag}</span></div>
            {!d.profiles_collected ? (
              <div className="px-1.5 text-text-secondary">профили политик не собраны — что включает тег, неизвестно</div>
            ) : profiles.length === 0 ? (
              <div className="px-1.5 text-text-secondary">ни один профиль не использует этот тег</div>
            ) : (
              <ul className="flex flex-col gap-0.5">
                {profiles.map((p) => {
                  const policyUrl = `/ksc/servers/${serverId}/policies/${p.policy_id}`
                  return (
                    <li key={`${p.policy_id}|${p.profile}`} className="flex items-center gap-2 px-1.5 py-0.5">
                      <Link to={policyUrl} className="min-w-0 truncate text-text hover:text-primary hover:underline" title={p.policy_name}>{p.policy_name}</Link>
                      <span className="shrink-0 text-text-secondary" aria-hidden>→</span>
                      <Link to={`${policyUrl}?tab=profiles`} className="min-w-0 truncate text-text hover:text-primary hover:underline" title={p.profile}>профиль {p.profile}</Link>
                      {!p.enabled && <span className="shrink-0 text-text-secondary">выключен</span>}
                    </li>
                  )
                })}
              </ul>
            )}
          </div>
        )
      })}
    </div>
  )
}
