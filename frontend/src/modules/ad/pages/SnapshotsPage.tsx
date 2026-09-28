import { useDeleteSnapshot, useReanalyze, useSnapshots } from '@/modules/ad/api/queries'
import { CollectorSnapshotsPage } from '@/platform/collector/SnapshotsPage'

export function SnapshotsPage({ domainId }: { domainId: number }) {
  const snapshots = useSnapshots(domainId)
  const reanalyze = useReanalyze()
  const remove = useDeleteSnapshot()
  return (
    <CollectorSnapshotsPage
      snapshots={snapshots}
      reanalyze={reanalyze}
      remove={remove}
      findingsPath={`/ad/domains/${domainId}/findings`}
      emptyDescription="Загрузите выгрузку или запустите сбор по LDAP в настройках."
      countHeader="Объектов"
      count={(s) => s.objects}
      source={(s) => (s.source === 'ldap' ? 'LDAP' : 'файл')}
      deleteNote="Находки и файл выгрузки будут удалены. Вердикты по домену останутся."
    />
  )
}
