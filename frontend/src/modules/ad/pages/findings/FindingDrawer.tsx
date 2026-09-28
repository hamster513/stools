import { useDropVerdict, useFindingDetail, useSetVerdict } from '@/modules/ad/api/queries'
import type { Finding } from '@/modules/ad/api/types'
import { CollectorFindingDrawer } from '@/platform/collector/FindingDrawer'

const HIDDEN = new Set(['details'])

export function FindingDrawer({ finding, snapshotId, domainId, onClose }: { finding: Finding | null; snapshotId: number | undefined; domainId: number; onClose: () => void }) {
  const accept = useSetVerdict()
  const drop = useDropVerdict()
  return (
    <CollectorFindingDrawer
      finding={finding}
      snapshotId={snapshotId}
      scope={{ domain_id: domainId }}
      useFindingDetail={useFindingDetail}
      accept={accept}
      drop={drop}
      leadRows={(d) => (
        <>
          <dt className="text-text-secondary">Identity</dt><dd className="font-mono break-all text-text">{d.identity || '—'} {d.identity_sid && <span className="text-[10px] text-text-secondary">{d.identity_sid}</span>}</dd>
          <dt className="text-text-secondary">Цель</dt><dd className="font-mono break-all text-text">{d.target || '—'}</dd>
          {d.right && <><dt className="text-text-secondary">Право</dt><dd className="font-mono text-text">{d.right}</dd></>}
        </>
      )}
      hiddenDetails={HIDDEN}
      trailRows={(d) => typeof d.details.details === 'string' && <><dt className="text-text-secondary">Детали</dt><dd className="text-text">{d.details.details}</dd></>}
      reasonPlaceholder="Почему это норма: сервисная учётка, пароль 32 символа…"
      verdictNote="Вердикт привязан к домену и ключу находки: переживёт следующие снапшоты, пока находка не изменится."
      onClose={onClose}
    />
  )
}
