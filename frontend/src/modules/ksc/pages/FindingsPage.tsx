import { useFindings, useServers } from '@/modules/ksc/api/queries'
import { CollectorFindingsPage } from '@/platform/collector/FindingsPage'
import { FindingsTable } from './findings/FindingsTable'
import { FindingDrawer } from './findings/FindingDrawer'

/** Находки снапшота: по умолчанию — последнего снапшота сервера. */
export function FindingsPage({ serverId }: { serverId: number }) {
  const servers = useServers()
  const server = servers.data?.find((s) => s.id === serverId)
  return (
    <CollectorFindingsPage
      filtersKey="ksc-findings"
      loading={servers.isLoading}
      lastSnapshotId={server?.last_snapshot_id ?? undefined}
      useFindings={useFindings}
      searchFromUrl
      searchPlaceholder="Хост, группа, проверка… (/)"
      emptyDescription="Загрузите выгрузку или запустите сбор из KSC в настройках модуля."
      table={(p) => <FindingsTable {...p} />}
      drawer={(finding, snapshotId, onClose) => <FindingDrawer finding={finding} snapshotId={snapshotId} serverId={serverId} onClose={onClose} />}
    />
  )
}
