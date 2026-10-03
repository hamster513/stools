import { Layers } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { usePolicyProfiles } from '@/modules/ksc/api/queries'
import type { PolicyProfile } from '@/modules/ksc/api/types'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { cn } from '@/lib/cn'
import { LockMark } from './RawTab'

function Errors({ errors }: { errors: string[] }) {
  if (errors.length === 0) return null
  return (
    <div className="mb-3 rounded border border-risk-medium/40 bg-risk-medium/5 px-3 py-2 text-xs text-text">
      Ошибки чтения профилей: {errors.join('; ')}
    </div>
  )
}

function ProfileBlock({ profile }: { profile: PolicyProfile }) {
  return (
    <details className="rounded border border-grid bg-surface" open>
      <summary className="cursor-pointer px-3 py-2 text-xs font-semibold text-text select-none">
        {profile.name}{' '}
        <span className="font-normal text-text-secondary">
          — приоритет {profile.priority} · <span className={profile.enabled ? 'text-kind-accepted' : undefined}>{profile.enabled ? 'включён' : 'выключен'}</span> · настроек {profile.settings}
        </span>
      </summary>
      <div className="px-3 pb-3">
        <Errors errors={profile.errors} />
        <div className="mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">Условие активации</div>
        <pre className="mb-3 max-h-64 overflow-auto rounded border border-grid bg-app-bg px-2 py-1.5 font-mono text-[11px] text-text">{JSON.stringify(profile.condition, null, 2)}</pre>
        <div className="mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">Отличия от политики</div>
        {profile.diff.length === 0 ? (
          <p className="text-xs text-text-secondary">Профиль не задаёт своих настроек.</p>
        ) : (
          <table className="w-full text-xs">
            <thead className="text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
              <tr>
                <th className="w-2/5 py-1 pr-3 text-left">Секция · путь</th>
                <th className="py-1 pr-3 text-left">В профиле</th>
                <th className="py-1 pr-3 text-left">В политике</th>
                <th className="py-1 pr-1 text-left">Замок</th>
              </tr>
            </thead>
            <tbody>
              {profile.diff.map((d) => (
                <tr key={`${d.section}|${d.path}`} className="border-t border-grid align-top">
                  <td className="py-1.5 pr-3 font-mono break-all text-text"><span className="text-text-secondary">{d.section} · </span>{d.path}</td>
                  <td className="py-1.5 pr-3 font-mono break-all text-text">{d.value}</td>
                  <td className={cn('py-1.5 pr-3 font-mono break-all', d.policy_value === null ? 'text-text-secondary italic' : 'text-text')}>
                    {d.policy_value ?? 'нет в политике'}
                  </td>
                  <td className="py-1.5 pr-1 whitespace-nowrap"><LockMark locked={d.locked} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </details>
  )
}

/** Вкладка «Профили»: профили политики по приоритету — включённость, условие активации, отличия от политики. */
export function ProfilesTab({ snapshotId, policyId }: { snapshotId: number; policyId: number }) {
  const profiles = usePolicyProfiles(snapshotId, policyId)

  if (profiles.isLoading) return <FullPageSpinner />
  if (profiles.isError || !profiles.data) {
    const msg = profiles.error instanceof ApiRequestError ? profiles.error.message : 'Не удалось загрузить профили политики'
    return <ErrorState message={msg} onRetry={() => profiles.refetch()} />
  }
  const { collected, errors } = profiles.data
  const items = [...profiles.data.profiles].sort((a, b) => a.priority - b.priority)

  if (!collected) {
    return (
      <>
        <Errors errors={errors} />
        <EmptyState icon={Layers} title="Профили не собраны" description="Профили политик читает сборщик версии 1.2 и новее; у политик агента и сервера профилей нет." />
      </>
    )
  }
  return (
    <>
      <Errors errors={errors} />
      {items.length === 0 ? (
        <EmptyState icon={Layers} title="Профилей нет" description="Профили собраны, у этой политики их нет." />
      ) : (
        <div className="flex flex-col gap-2">
          {items.map((p) => (
            <ProfileBlock key={`${p.priority}|${p.name}`} profile={p} />
          ))}
        </div>
      )}
    </>
  )
}
