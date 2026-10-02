import { useFindingDetail } from '@/modules/ad/api/queries'
import type { Finding } from '@/modules/ad/api/types'
import { CollectorFindingDrawer } from '@/platform/collector/FindingDrawer'

const HIDDEN = new Set(['details'])

export function FindingDrawer({ findingKey, snapshotId, domainId, onChanged, onClose }: { findingKey: string | null; snapshotId: number | undefined; domainId: number; onChanged: () => void; onClose: () => void }) {
  return (
    <CollectorFindingDrawer<Finding>
      findingKey={findingKey}
      snapshotId={snapshotId}
      module="ad"
      scopeId={domainId}
      useFindingDetail={useFindingDetail}
      titleOf={(d) => `${d.check_title}: ${d.identity || d.target}`}
      leadRows={(d) => (
        <>
          <dt className="text-text-secondary">Identity</dt><dd className="font-mono break-all text-text">{d.identity || '—'} {d.identity_sid && <span className="text-[10px] text-text-secondary">{d.identity_sid}</span>}</dd>
          <dt className="text-text-secondary">Цель</dt><dd className="font-mono break-all text-text">{d.target || '—'}</dd>
          {d.right && <><dt className="text-text-secondary">Право</dt><dd className="font-mono text-text">{d.right}</dd></>}
        </>
      )}
      hiddenDetails={HIDDEN}
      trailRows={(d) => typeof d.details.details === 'string' && <><dt className="text-text-secondary">Детали</dt><dd className="text-text">{d.details.details}</dd></>}
      onChanged={onChanged}
      onClose={onClose}
    />
  )
}
