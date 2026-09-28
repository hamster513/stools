import { useDeleteSnapshot, useReanalyze, useSnapshots } from '@/modules/ksc/api/queries'
import { CollectorSnapshotsPage } from '@/platform/collector/SnapshotsPage'

export function SnapshotsPage({ serverId }: { serverId: number }) {
  const snapshots = useSnapshots(serverId)
  const reanalyze = useReanalyze()
  const remove = useDeleteSnapshot()
  return (
    <CollectorSnapshotsPage
      snapshots={snapshots}
      reanalyze={reanalyze}
      remove={remove}
      findingsPath={`/ksc/servers/${serverId}/findings`}
      emptyDescription="Загрузите выгрузку или запустите сбор из KSC в настройках."
      countHeader="Хостов"
      count={(s) => s.hosts}
      source={(s) => (s.source === 'online' ? 'Сбор из KSC' : 'файл')}
      deleteNote="Находки, инвентарь хостов и файл выгрузки будут удалены. Вердикты по серверу останутся."
    />
  )
}
