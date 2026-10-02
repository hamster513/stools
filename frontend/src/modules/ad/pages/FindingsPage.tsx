import { useDomains, useFindings, useFindingsChanged } from '@/modules/ad/api/queries'
import { CollectorFindingsPage } from '@/platform/collector/FindingsPage'
import { FindingsTable } from './findings/FindingsTable'
import { FindingDrawer } from './findings/FindingDrawer'

/** Находки снапшота: по умолчанию — последнего снапшота домена. */
export function FindingsPage({ domainId }: { domainId: number }) {
  const domains = useDomains()
  const changed = useFindingsChanged()
  const domain = domains.data?.find((d) => d.id === domainId)
  return (
    <CollectorFindingsPage
      module="ad"
      scopeId={domainId}
      onChanged={changed}
      filtersKey="ad-findings"
      loading={domains.isLoading}
      lastSnapshotId={domain?.last_snapshot_id ?? undefined}
      useFindings={useFindings}
      searchFromUrl
      searchPlaceholder="Identity, цель, право… (/)"
      emptyDescription="Загрузите выгрузку или запустите сбор по LDAP в настройках модуля."
      table={(p) => <FindingsTable {...p} />}
      drawer={(findingKey, snapshotId, onClose) => <FindingDrawer findingKey={findingKey} snapshotId={snapshotId} domainId={domainId} onChanged={changed} onClose={onClose} />}
    />
  )
}
