import { useMemo, useState } from 'react'
import { ArrowLeft, FileWarning, Lock, LockOpen, Search, ShieldQuestion } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { usePolicyContents, useServers } from '@/modules/ksc/api/queries'
import type { PolicySection, PolicySetting } from '@/modules/ksc/api/types'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { Link } from '@/lib/router'
import { cn } from '@/lib/cn'

const HIDDEN_VALUE = '"<скрыто>"'

function LockIcon({ setting }: { setting: PolicySetting }) {
  if (setting.locked === null) return <span className="text-text-secondary" title="признак замка не пришёл">—</span>
  if (!setting.locked) return <LockOpen size={13} className="text-text-secondary" aria-hidden />
  const title = setting.inherited_lock && setting.lock_from ? `замок из политики ${setting.lock_from}` : 'замкнута в этой политике'
  return <span title={title}><Lock size={13} className="text-risk-high" aria-hidden /></span>
}

function SettingRow({ setting }: { setting: PolicySetting }) {
  const hidden = setting.value === HIDDEN_VALUE
  return (
    <tr className="border-t border-grid align-top">
      <td className="py-1.5 pr-3 font-mono text-xs text-text">{setting.path}</td>
      <td className={cn('py-1.5 pr-3 font-mono text-xs break-all', hidden ? 'text-text-secondary italic' : 'text-text')}>{setting.value}</td>
      <td className="py-1.5 pr-1 whitespace-nowrap"><LockIcon setting={setting} /></td>
    </tr>
  )
}

function SectionBlock({ section }: { section: PolicySection }) {
  return (
    <details className="rounded border border-grid bg-surface" open>
      <summary className="cursor-pointer px-3 py-2 text-xs font-semibold text-text select-none">
        {section.name} <span className="font-normal text-text-secondary">— настроек {section.settings.length}</span>
      </summary>
      <table className="w-full text-xs">
        <thead className="text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
          <tr>
            <th className="w-1/2 py-1 pr-3 pl-3 text-left">Путь</th>
            <th className="py-1 pr-3 text-left">Значение</th>
            <th className="py-1 pr-1 text-left">Замок</th>
          </tr>
        </thead>
        <tbody>
          {section.settings.map((s) => (
            <SettingRow key={s.path} setting={s} />
          ))}
        </tbody>
      </table>
    </details>
  )
}

/** Содержимое политики: сводка замков, фильтр по замку и поиск по пути, секции сворачиваются. */
export function PolicyContentsPage({ serverId, policyId }: { serverId: number; policyId: number }) {
  const servers = useServers()
  const server = servers.data?.find((s) => s.id === serverId)
  const snapshotId = server?.last_snapshot_id ?? undefined
  const contents = usePolicyContents(snapshotId, policyId)
  const [onlyUnlocked, setOnlyUnlocked] = useState(false)
  const [query, setQuery] = useState('')
  const debouncedQuery = useDebouncedValue(query, 200)

  const sections = useMemo(() => {
    if (!contents.data) return []
    const q = debouncedQuery.trim().toLowerCase()
    return contents.data.sections
      .map((s) => ({
        ...s,
        settings: s.settings.filter((st) => (!onlyUnlocked || st.locked !== true) && (!q || st.path.toLowerCase().includes(q))),
      }))
      .filter((s) => s.settings.length > 0)
  }, [contents.data, onlyUnlocked, debouncedQuery])

  if (servers.isLoading) return <FullPageSpinner />
  if (snapshotId === undefined) {
    return <div className="p-6"><EmptyState icon={ShieldQuestion} title="Снапшотов нет" description="Загрузите выгрузку или запустите сбор из KSC в настройках модуля." /></div>
  }
  if (contents.isLoading) return <FullPageSpinner />
  if (contents.isError || !contents.data) {
    const msg = contents.error instanceof ApiRequestError ? contents.error.message : 'Не удалось загрузить содержимое политики'
    return <div className="p-6"><ErrorState message={msg} onRetry={() => contents.refetch()} /></div>
  }

  const { policy, summary, errors } = contents.data

  return (
    <div className="h-full overflow-y-auto p-6">
      <Link to={`/ksc/servers/${serverId}/policies`} className="mb-3 inline-flex items-center gap-1 text-xs text-text-secondary hover:text-text">
        <ArrowLeft size={13} aria-hidden /> к политикам и задачам
      </Link>
      <div className="mb-4">
        <h1 className="text-base font-semibold text-text">{policy.name}</h1>
        <p className="mt-0.5 flex flex-wrap items-center gap-x-3 text-xs text-text-secondary">
          <span>{policy.product}{policy.version ? ` ${policy.version}` : ''}</span>
          <span>группа {policy.group || '—'}</span>
          {summary && summary.with_lock_flag > 0 && (
            <span>замков {summary.locked} из {summary.with_lock_flag} ({Math.round(summary.share * 100)}%)</span>
          )}
          {summary && summary.with_lock_flag > 0 && summary.with_lock_flag < summary.total && (
            <span>без признака замка {summary.total - summary.with_lock_flag}</span>
          )}
        </p>
      </div>

      {!summary ? (
        <EmptyState icon={FileWarning} title="Содержимого нет" description={errors[0] ?? 'Содержимое этой политики не собрано.'} />
      ) : (
        <>
          {summary.with_lock_flag === 0 && (
            <div className="mb-3 rounded border border-grid bg-surface px-3 py-2 text-xs text-text-secondary">
              Замки в этой политике не распознаны: ни у одной настройки нет признака замка, проверки замков её не оценивают.
            </div>
          )}
          {errors.length > 0 && (
            <div className="mb-3 rounded border border-risk-medium/40 bg-risk-medium/5 px-3 py-2 text-xs text-text">
              Не прочитались секции: {errors.join('; ')}
            </div>
          )}
          <div className="mb-3 flex flex-wrap items-center gap-3">
            <label className="flex items-center gap-1.5 text-xs text-text">
              <input type="checkbox" className="accent-primary" checked={onlyUnlocked} onChange={(e) => setOnlyUnlocked(e.target.checked)} />
              <span>только незамкнутые</span>
            </label>
            <label className="relative flex items-center">
              <Search size={13} className="pointer-events-none absolute left-2 text-text-secondary" aria-hidden />
              <input
                className="w-64 rounded border border-border bg-app-bg py-1.5 pr-2 pl-7 text-xs text-text placeholder:text-text-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
                placeholder="поиск по пути"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
            </label>
          </div>
          {sections.length === 0 ? (
            <EmptyState icon={ShieldQuestion} title="Ничего не найдено" description="Измените фильтр или поиск." />
          ) : (
            <div className="flex flex-col gap-2">
              {sections.map((s) => (
                <SectionBlock key={s.name} section={s} />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  )
}
