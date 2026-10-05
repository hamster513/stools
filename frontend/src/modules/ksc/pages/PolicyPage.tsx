import { AlertTriangle, ArrowLeft, ShieldQuestion } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { usePolicy, useServers } from '@/modules/ksc/api/queries'
import type { PolicyCard } from '@/modules/ksc/api/types'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { Link, useSearchParams } from '@/lib/router'
import { GradeBadge } from './policies/GradeBadge'
import { TabBar, type TabDef } from './policies/TabBar'
import { GradeTab } from './policy/GradeTab'
import { ProfilesTab } from './policy/ProfilesTab'
import { RawTab } from './policy/RawTab'
import { ScopeTab } from './policy/ScopeTab'
import { SettingsTab } from './policy/SettingsTab'
import { ExclusionsTable } from './ExclusionsPage'
import { NetRulesTable } from './NetRulesPage'
import { ChangesList } from './ChangesPage'

const TABS: TabDef[] = [
  { key: 'grade', label: 'Оценка' },
  { key: 'settings', label: 'Настройки' },
  { key: 'profiles', label: 'Профили' },
  { key: 'exclusions', label: 'Исключения' },
  { key: 'netrules', label: 'Сетевые правила' },
  { key: 'scope', label: 'Где действует' },
  { key: 'changes', label: 'Изменения' },
  { key: 'raw', label: 'Все поля' },
]

/** Вкладка без `?tab=`: «Оценка», если оценка есть или есть считаемые находки, иначе «Где действует». */
function defaultTab(p: PolicyCard): TabDef {
  return TABS.find((t) => t.key === (p.grade !== null || p.findings > 0 ? 'grade' : 'scope')) ?? TABS[0]
}

/** Вкладки со своей панелью фильтров и прокруткой: без отступов вокруг. */
const FULL_TABS = new Set(['exclusions', 'netrules', 'changes'])

/** Счётчик, которому нечего показать без содержимого или описания продукта: «—» с причиной, а не «0». */
function objectsCount(p: PolicyCard, n: number): string {
  if (!p.has_contents) return '— (содержимое не собрано)'
  if (!p.described) return '— (продукт не описан)'
  return String(n)
}

function Counters({ p, serverId }: { p: PolicyCard; serverId: number }) {
  return (
    <p className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 text-xs text-text-secondary">
      <span>групп {p.groups}</span>
      <span>хостов {p.hosts}</span>
      <span>профилей {p.profiles === null ? 'не собрано' : p.profiles}</span>
      <span>исключений {objectsCount(p, p.exclusions)}</span>
      <span>сетевых правил {objectsCount(p, p.net_rules)}</span>
      <span>
        {p.locks === null ? 'замки — (содержимое не собрано)' : p.locks.with_lock_flag === 0 ? 'замки не распознаны' : `замков ${p.locks.locked} из ${p.locks.with_lock_flag}`}
      </span>
      {p.has_contents && <span>распознано {p.settings_known} из {p.settings_total} настроек</span>}
      <span>изменений {p.changes}</span>
      {p.findings > 0 ? (
        <Link to={`/ksc/servers/${serverId}/findings?q=${encodeURIComponent(p.name)}`} className="text-primary hover:underline">находок {p.findings}</Link>
      ) : (
        <span>находок 0</span>
      )}
    </p>
  )
}

/** Карточка политики снапшота: шапка со сводом и вкладки `?tab=` — оценка, настройки, профили, исключения, сетевые правила, где действует, изменения, все поля. */
export function PolicyPage({ serverId, policyId }: { serverId: number; policyId: number }) {
  const params = useSearchParams()
  const servers = useServers()
  const server = servers.data?.find((s) => s.id === serverId)
  const snapshotId = server?.last_snapshot_id ?? undefined
  const policy = usePolicy(snapshotId, policyId)
  const requested = TABS.find((t) => t.key === params.get('tab'))

  if (servers.isLoading) return <FullPageSpinner />
  if (snapshotId === undefined) {
    return <div className="p-6"><EmptyState icon={ShieldQuestion} title="Снапшотов нет" description="Загрузите выгрузку или запустите сбор из KSC в настройках модуля." /></div>
  }
  if (policy.isLoading) return <FullPageSpinner />
  if (policy.isError || !policy.data) {
    const msg = policy.error instanceof ApiRequestError ? policy.error.message : 'Не удалось загрузить политику'
    return <div className="p-6"><ErrorState message={msg} onRetry={() => policy.refetch()} /></div>
  }
  const p = policy.data
  const tab = requested ?? defaultTab(p)

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="shrink-0 border-b border-grid bg-surface px-4 pt-2.5">
        <Link to={`/ksc/servers/${serverId}/policies`} className="mb-2 inline-flex items-center gap-1 text-xs text-text-secondary hover:text-text">
          <ArrowLeft size={13} aria-hidden /> к политикам и задачам
        </Link>
        <div className="flex flex-wrap items-baseline gap-x-3">
          <h1 className="text-base font-semibold text-text">{p.name}</h1>
          <span className="text-xs"><GradeBadge grade={p.grade} reason={p.grade_reason} /></span>
        </div>
        <p className="mt-0.5 flex flex-wrap items-center gap-x-3 text-xs text-text-secondary">
          <span>{p.product}{p.version ? ` ${p.version}` : ''}</span>
          <span>группа {p.group || '—'}</span>
          {!p.active && <span>неактивна</span>}
          {!p.accept_parent && <span className="flex items-center gap-1 text-risk-medium"><AlertTriangle size={11} aria-hidden /> не принимает родительскую</span>}
        </p>
        <Counters p={p} serverId={serverId} />
        {p.errors.length > 0 && (
          <div className="mt-2 rounded border border-risk-medium/40 bg-risk-medium/5 px-3 py-2 text-xs text-text">
            Ошибки сбора: {p.errors.join('; ')}
          </div>
        )}
        <div className="mt-2">
          <TabBar tabs={TABS} current={tab.key} label="Карточка политики" />
        </div>
      </header>
      <div role="tabpanel" aria-label={tab.label} className={FULL_TABS.has(tab.key) ? 'min-h-0 flex-1' : 'min-h-0 flex-1 overflow-y-auto p-6'}>
        {tab.key === 'grade' && <GradeTab serverId={serverId} snapshotId={snapshotId} policy={p} />}
        {tab.key === 'settings' && <SettingsTab serverId={serverId} snapshotId={snapshotId} policy={p} />}
        {tab.key === 'scope' && <ScopeTab serverId={serverId} snapshotId={snapshotId} policyId={policyId} />}
        {tab.key === 'profiles' && <ProfilesTab snapshotId={snapshotId} policyId={policyId} />}
        {tab.key === 'exclusions' && <ExclusionsTable snapshotId={snapshotId} serverId={serverId} policyId={policyId} />}
        {tab.key === 'netrules' && <NetRulesTable snapshotId={snapshotId} serverId={serverId} policyId={policyId} />}
        {tab.key === 'changes' && <ChangesList serverId={serverId} policyId={policyId} />}
        {tab.key === 'raw' && <RawTab snapshotId={snapshotId} policyId={policyId} />}
      </div>
    </div>
  )
}
