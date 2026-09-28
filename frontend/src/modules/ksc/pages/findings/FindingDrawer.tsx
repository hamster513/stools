import { useDropVerdict, useFindingDetail, useSetVerdict } from '@/modules/ksc/api/queries'
import type { Finding } from '@/modules/ksc/api/types'
import { CollectorFindingDrawer } from '@/platform/collector/FindingDrawer'

export function FindingDrawer({ finding, snapshotId, serverId, onClose }: { finding: Finding | null; snapshotId: number | undefined; serverId: number; onClose: () => void }) {
  const accept = useSetVerdict()
  const drop = useDropVerdict()
  return (
    <CollectorFindingDrawer
      finding={finding}
      snapshotId={snapshotId}
      scope={{ server_id: serverId }}
      useFindingDetail={useFindingDetail}
      accept={accept}
      drop={drop}
      leadRows={(d) => (
        <>
          <dt className="text-text-secondary">Хост</dt><dd className="font-mono break-all text-text">{d.host || '—'}</dd>
          <dt className="text-text-secondary">Цель</dt><dd className="font-mono break-all text-text">{d.target || '—'}</dd>
        </>
      )}
      reasonPlaceholder="Почему это норма: тестовый стенд, отдельная политика…"
      verdictNote="Вердикт привязан к серверу и ключу находки: переживёт следующие снапшоты, пока находка не изменится."
      onClose={onClose}
    />
  )
}
