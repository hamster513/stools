import { useFindingDetail } from '@/modules/ksc/api/queries'
import type { Finding } from '@/modules/ksc/api/types'
import { CollectorFindingDrawer } from '@/platform/collector/FindingDrawer'

export function FindingDrawer({ findingKey, snapshotId, serverId, onChanged, onClose }: { findingKey: string | null; snapshotId: number | undefined; serverId: number; onChanged: () => void; onClose: () => void }) {
  return (
    <CollectorFindingDrawer<Finding>
      findingKey={findingKey}
      snapshotId={snapshotId}
      module="ksc"
      scopeId={serverId}
      useFindingDetail={useFindingDetail}
      titleOf={(d) => `${d.check_title}: ${d.host || d.target}`}
      leadRows={(d) => (
        <>
          <dt className="text-text-secondary">Хост</dt><dd className="font-mono break-all text-text">{d.host || '—'}</dd>
          <dt className="text-text-secondary">Цель</dt><dd className="font-mono break-all text-text">{d.target || '—'}</dd>
        </>
      )}
      onChanged={onChanged}
      onClose={onClose}
    />
  )
}
