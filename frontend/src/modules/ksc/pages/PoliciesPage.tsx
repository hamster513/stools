import { FolderTree } from 'lucide-react'
import { useServers } from '@/modules/ksc/api/queries'
import { EmptyState } from '@/components/ui/EmptyState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useSearchParams } from '@/lib/router'
import { GroupsTree } from './policies/GroupsTree'
import { PoliciesTable } from './policies/PoliciesTable'
import { TabBar, type TabDef } from './policies/TabBar'
import { TasksTable } from './policies/TasksTable'

const TABS: TabDef[] = [
  { key: 'policies', label: 'Политики' },
  { key: 'tasks', label: 'Задачи' },
  { key: 'groups', label: 'По группам' },
]

/** «Политики и задачи» снапшота: плоские списки политик и задач и прежнее дерево групп — вкладками `?tab=`. */
export function PoliciesPage({ serverId }: { serverId: number }) {
  const params = useSearchParams()
  const servers = useServers()
  const server = servers.data?.find((s) => s.id === serverId)
  const snapshotId = server?.last_snapshot_id ?? undefined
  const tab = TABS.find((t) => t.key === params.get('tab')) ?? TABS[0]

  if (servers.isLoading) return <FullPageSpinner />
  if (snapshotId === undefined) {
    return <div className="p-6"><EmptyState icon={FolderTree} title="Снапшотов нет" description="Загрузите выгрузку или запустите сбор из KSC в настройках модуля." /></div>
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex shrink-0 flex-wrap items-end gap-x-6 border-b border-grid bg-surface px-4 pt-2.5">
        <div className="flex items-baseline gap-3 pb-2">
          <h1 className="text-sm font-semibold text-text">Политики и задачи</h1>
          <span className="font-mono text-xs text-text-secondary">снапшот #{snapshotId}</span>
        </div>
        <TabBar tabs={TABS} current={tab.key} label="Политики и задачи" />
      </header>
      <div role="tabpanel" aria-label={tab.label} className="min-h-0 flex-1">
        {tab.key === 'policies' && <PoliciesTable serverId={serverId} snapshotId={snapshotId} />}
        {tab.key === 'tasks' && <TasksTable snapshotId={snapshotId} />}
        {tab.key === 'groups' && <GroupsTree serverId={serverId} snapshotId={snapshotId} />}
      </div>
    </div>
  )
}
