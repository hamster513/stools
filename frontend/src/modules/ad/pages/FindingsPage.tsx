import { useDomains, useFindings } from '@/modules/ad/api/queries'
import { CollectorFindingsPage } from '@/platform/collector/FindingsPage'
import { FindingsTable } from './findings/FindingsTable'
import { FindingDrawer } from './findings/FindingDrawer'

/** Находки снапшота: по умолчанию — последнего снапшота домена. */
export function FindingsPage({ domainId }: { domainId: number }) {
  const domains = useDomains()
  const domain = domains.data?.find((d) => d.id === domainId)
  return (
    <CollectorFindingsPage
      filtersKey="ad-findings"
      loading={domains.isLoading}
      lastSnapshotId={domain?.last_snapshot_id ?? undefined}
      useFindings={useFindings}
      searchFromUrl
      searchPlaceholder="Identity, цель, право… (/)"
      emptyDescription="Загрузите выгрузку или запустите сбор по LDAP в настройках модуля."
      table={(p) => <FindingsTable {...p} />}
      drawer={(finding, snapshotId, onClose) => <FindingDrawer finding={finding} snapshotId={snapshotId} domainId={domainId} onClose={onClose} />}
    />
  )
}
