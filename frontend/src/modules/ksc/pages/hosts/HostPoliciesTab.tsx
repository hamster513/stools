import { ApiRequestError } from '@/api/client'
import { useHostProfiles } from '@/modules/ksc/api/queries'
import type { HostProfile, HostProfilesPolicy } from '@/modules/ksc/api/types'
import { ErrorState } from '@/components/ui/ErrorState'
import { Spinner } from '@/components/ui/Spinner'
import { cn } from '@/lib/cn'
import { Link } from '@/lib/router'

/** Условие активации словами: внутри группы «и», между группами «или»; пусто — правил активации нет. */
function conditionText(condition: HostProfile['condition']): string {
  return condition.map((g) => g.map((c) => c.text).join(' и ')).join('; или ')
}

/** Активация профиля на хосте: зелёным — активен, жёлтым — не определить; причина приходит с сервера. */
function activation(p: HostProfile): { label: string; className: string } {
  if (p.active === true) return { label: `активен — ${p.reason}`, className: 'text-kind-accepted' }
  if (p.active === false) return { label: `не активен — ${p.reason}`, className: 'text-text-secondary' }
  return { label: `не определить — ${p.reason}`, className: 'text-risk-medium' }
}

/** У политики с неописанным продуктом записей нет потому, что извлекателя нет, — число не показывается. */
function counts(p: HostProfile): string {
  if (p.exclusions === null || p.net_rules === null) return `настроек ${p.settings} · структура продукта не описана`
  return `настроек ${p.settings} · исключений ${p.exclusions} · правил ${p.net_rules}`
}

function ProfileRow({ p }: { p: HostProfile }) {
  const a = activation(p)
  const condition = conditionText(p.condition)
  return (
    <li className="rounded border border-grid bg-app-bg px-3 py-2">
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
        <span className="font-medium text-text">{p.name}</span>
        <span className="text-text-secondary">приоритет {p.priority}</span>
        {!p.enabled && <span className="text-text-secondary">выключен</span>}
        <span className={cn('ml-auto', a.className)}>{a.label}</span>
      </div>
      {condition && <div className="mt-0.5 text-text-secondary">условие: {condition}</div>}
      <div className="mt-0.5 text-text-secondary">{counts(p)}</div>
    </li>
  )
}

function PolicyBlock({ policy, serverId }: { policy: HostProfilesPolicy; serverId: number }) {
  const profiles = [...policy.profiles].sort((a, b) => a.priority - b.priority)
  return (
    <div className="mb-3">
      <div className="flex items-center gap-2 px-1.5 py-1">
        <Link to={`/ksc/servers/${serverId}/policies/${policy.id}`} className="min-w-0 flex-1 truncate text-text hover:text-primary hover:underline" title={policy.name}>{policy.name}</Link>
        <span className="shrink-0 text-[11px] text-text-secondary">{policy.product}</span>
        <span className="shrink-0 text-[11px] text-text-secondary">{policy.own ? 'своя' : 'унаследована'}</span>
        {!policy.active && <span className="shrink-0 text-[11px] text-risk-medium">неактивна</span>}
      </div>
      {!policy.profiles_collected ? (
        <div className="px-1.5 text-text-secondary">профили не собраны</div>
      ) : profiles.length === 0 ? (
        <div className="px-1.5 text-text-secondary">профилей нет</div>
      ) : (
        <ul className="flex flex-col gap-1">{profiles.map((p) => <ProfileRow key={`${p.priority}|${p.name}`} p={p} />)}</ul>
      )}
    </div>
  )
}

function Note({ children }: { children: string }) {
  return <div className="mb-3 rounded border border-risk-medium/40 bg-risk-medium/5 px-3 py-2 text-xs text-text">{children}</div>
}

/** Вкладка «Политики и профили» панели хоста: политики группы хоста, под каждой — профили по приоритету и их активация на этом хосте по тегам. */
export function HostPoliciesTab({ snapshotId, hostId, serverId }: { snapshotId: number; hostId: string; serverId: number }) {
  const query = useHostProfiles(snapshotId, hostId)
  if (query.isLoading) return <div className="flex justify-center py-8"><Spinner /></div>
  if (query.isError || !query.data) {
    const msg = query.error instanceof ApiRequestError ? query.error.message : 'Не удалось загрузить профили хоста'
    return <ErrorState message={msg} onRetry={() => query.refetch()} />
  }
  const d = query.data
  return (
    <>
      {!d.profiles_collected && <Note>Профили политик в снапшоте не собраны — активация профилей на хосте неизвестна. Профили читает сборщик версии 1.2 и новее.</Note>}
      {d.profiles_collected && d.tags === null && <Note>Теги хоста не собраны — активацию профилей по тегам не определить.</Note>}
      <div className="mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">Политики ({d.policies.length})</div>
      {d.policies.length === 0 && <div className="text-text-secondary">нет действующих политик</div>}
      {d.policies.map((p) => <PolicyBlock key={p.id} policy={p} serverId={serverId} />)}
    </>
  )
}
